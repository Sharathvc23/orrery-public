# Trust model — what Orrery records, and what a reader may conclude from it

This page states exactly what each kind of action leaves behind, who can
verify it, and how far a verifier's conclusion is allowed to go. Every claim
here is tied to a code symbol or a named test, written as `path::symbol` or
`path::test_name`; `tests/test_trust_model_citations.py` refuses this page
if any cited file or symbol stops existing, so the page cannot outlive its
evidence. It is the reference the security policy and the audit ledger
point at when they say "signed" or "verifiable": those words have a precise
scope, and this is where the scope is written down.

The one rule that governs the whole page: **a valid signature proves who
produced some bytes. It does not prove that what the bytes describe
happened, and a valid chain does not prove that it is complete.** Each
section below says what a given artifact adds on top of that floor.

---

## 1. What is mediated, and what is recorded

| Action kind | Where it is mediated | What is recorded, and where | Who can verify what |
|---|---|---|---|
| **A2A call to another agent** | `agent/community_member/a2a_client_v2.py::send_task_recorded` — a `pending` attempt is written to the Agency Log first (`agent/community_member/arp.py::AgencyLog.begin_action`), then the call runs, then `agent/community_member/interactions.py::record_interaction` builds, co-signs and signs the receipt and the attempt is finalized `succeeded`, `failed` or `unknown` (`agent/tests/test_execution_receipt_ordering.py::test_T1_kill_after_call_before_receipt_write_surfaces_UNKNOWN_on_restart`). A receipt is emitted only for an observed success; an attempt whose outcome nobody observed stays in the log as `unknown` and is never retried by the runtime. | One ARP receipt, signed by the caller's key, in the caller's **Agency Log** (`agent/community_member/arp.py::AgencyLog`, local SQLite). It names the counterparty by DID (`action.counterparty_did`). When the counterparty agrees it carries a co-signature in `evidence.witness_signatures` (`agent/community_member/cosign.py::attach_corroboration`). It reaches the org only if pushed (`agent/community_member/arp.py::_push_to_chapter`) or submitted to `POST /api/receipts`. | **Anyone holding the receipt**: signature (`agent/community_member/arp.py::verify_receipt_signature`) and corroboration (`sm_arp.vrp.is_corroborated`) recompute offline against the `did:key`s the receipt names — the recipe is [`VERIFY_A_RECEIPT.md`](./VERIFY_A_RECEIPT.md). **Only the owner** can read the Agency Log itself; `GET /api/receipts` on the org is authenticated. |
| **Booking skill** | `agent/community_member/builtin_skills/booking/skill.py::book_appointment` | A `pending` attempt is persisted **before** the booking row (`agent/tests/test_booking_skill.py::test_the_attempt_is_persisted_before_the_booking`), so no booking exists without a record of it; the receipt (`appointment_booked`) is signed only **after** the booking is written, so it never attests a booking that failed to store (`agent/tests/test_booking_store_integrity.py::test_a_receipt_that_fails_after_the_booking_is_written_is_owed_not_forged`). A keyless agent books without a receipt and says so. Delivery to the business runs **after** both, through `agent/community_member/builtin_skills/booking/notify.py::deliver`; its outcome is returned to the caller as `delivered` and is **not** in the receipt. | Same as above for the receipt. The delivery outcome is nobody's to verify: it is a webhook response (`agent/community_member/builtin_skills/booking/notify.py::WebhookSender`) reported in the tool result. |
| **Local capability execution** — `fs.read`, `fs.write`, `shell.exec`, `net.http`, `browser.*`, `desktop.*`, `skill.invoke` (`agent/community_member/executor.py::KNOWN_CAPABILITIES`) | `agent/community_member/executor.py::execute_plan` — every proposal passes the consent gate before a runner is invoked | **The authorization decision, not the execution.** The gate writes a consent-ledger row (`agent/community_member/consent/gate.py::record_decision` → `agent/community_member/consent/ledger.py`, hash-chained, signed when the agent has a key) and the same verdict as a signed, per-agent-chained sm-aae envelope (`agent/community_member/consent/aae_emit.py::emit_decision`). The runner's output lands in an `ExecutionResult` returned to the think loop. **No ARP receipt is emitted for a local execution.** The only receipt-emitting paths in the agent are the A2A client, the booking skill and the `interact` flow (`agent/community_member/flows.py`). | **Owner**: the ledger is local; an export re-derives (`agent/tests/consent/test_ledger_external_verify.py::test_clean_export_rederivable`). **Third party**: envelopes are exportable (`agent/community_member/aae_export.py`) and served at `GET /api/agents/{id}/aae-events` — to anyone only when the member opted into a public Chronicle, otherwise to the owner or an admin; the envelope proves the *decision* was signed, nothing about what the runner then did. |
| **Org-side privileged actions** (role changes, policy edits, revocations, invites, peer lifecycle) | The admin and leader routes in `server/chapter_agent.py` | A hash-chained audit row per action (`server/chapter_audit.py::record`; `server/chapter_audit.py::verify_chain` re-derives it). The org can sign a commitment to the chain tip (`POST /admin/api/audit/attest`, `server/chapter_audit.py::chain_tip`). Org-performed actions with a receipt shape — an outbound external send, a membership authority grant — are org-issued ARP receipts (`server/arp.py::emit_chapter_action`; `server/tests/test_register_member_emits_authority_grant.py`). | **Operator**: `GET /admin/api/audit`, `/admin/api/audit/verify`, `/admin/api/audit/export` (admin token). **Anyone**: only what the operator publishes — receipts the org issued about its own actions, as a bundle at `/.well-known/receipt-disclosure/{id}.json` (`server/receipt_publication.py`), verified against the org's `/.well-known/did.json`. |
| **Outbound email to a non-member** | `server/external_send.py` — the org performs the send; the agent never holds the provider key | An org receipt, `external_message_sent`, carrying the transport used and the transport's `delivered` flag (`server/external_send.py::_receipt`). Sandbox by default: without `KLAVIYO_LIVE_SENDS` and a key the transport cannot open a socket (`server/tests/test_external_send.py::test_the_sandbox_transport_contains_no_http_client`). Gated by an operational approval consumed immediately before the side effect (`server/tests/test_external_send.py::test_an_approved_grant_sends_exactly_once`). | Operator, and anyone the operator publishes the receipt to. `delivered` is the provider's response, recorded after the fact — see §2. |
| **Federation broadcast** | `server/federation_signing.py` | The outbound body is signed with the org key over body + timestamp + nonce; the receiver verifies against the sender's `/.well-known/did.json` and rejects on failure (`server/tests/test_federation_signing.py::test_tampered_body_invalid`, `::test_wrong_key_invalid`). A captured broadcast cannot be replayed after the freshness window, because the timestamp is signed; inside the window, replay is refused by an in-memory dedup ring that does not survive a receiver restart. | **The receiving peer**, at receipt time. There is no later re-verifiable artifact unless a party kept the signed body. |
| **Index / registry publication** | Agent: `agent/community_member/registry.py::should_announce` — fail-closed, requires an owner-signed listing grant on disk (`agent/community_member/owner.py::listing_grant_verdict`). Org: `server/registry_policy.py`. Member directory listing: `POST /api/me/listing` → `server/member_listing.py::consent_of` | The consent record. Agent-side, the owner's signed grant; org-side, the member's `listing` consent on the member row, which is also what gates `GET /api/agents/{id}/profile` (`server/tests/test_profile_consent_gate.py`). | The published record is public by construction. Whether a registry is serving it faithfully is a separate question — §4. |

Two things the table does not contain, because nothing in the tree produces
them: a receipt for a local capability execution, and a signed record of an
external outcome. Both are stated again in §2 because they are the two
places a reader is most likely to assume more than exists.

---

## 2. Four things a reader must not conflate

Each of these is a distinct artifact with a distinct scope. Treating one as
another is how "signed" becomes "true".

### 2.1 A signed claim — an ARP receipt

**What it is.** The issuer asserts, under its own key, that it performed an
action: `receipt.action`, `issuer_did`, `principal_did`, a timestamp, and a
link to the issuer's previous receipt (`agent/community_member/arp.py::build_receipt`,
`::sign_receipt`, `::receipt_chain_link`).

**What the signature proves.** That the holder of the private key behind
`issuer_did` produced these exact bytes, and that they have not changed since
(`agent/community_member/arp.py::verify_receipt_signature`). `did:key` is
self-certifying, so no registry is consulted for this step.

**What it does not prove.** That the action happened, that it happened as
described, or that the issuer's log contains every receipt it should. The
issuer wrote both the claim and the signature.

**Where it lives.** The issuer's Agency Log; the org's issuer log if pushed
or submitted; a published disclosure bundle if the org chose to publish it.

### 2.2 Authorization evidence — DAT, operational grants, consent decisions

**What it is.** A record of what an agent was *permitted* to do, produced
before or independently of doing it:

- **DAT** (Delegated Authority Token): a grantor-signed scope with a validity
  window, an optional sub-delegation chain and a revocation set, verified by
  the vendored canonical verifier (`agent/community_member/dat.py::verify_counterparty_dat`;
  `agent/tests/test_dat.py::test_expired_dat_rejected`,
  `::test_sub_delegation_cannot_widen_scope`, `::test_revoked_dat_rejected`).
  A sovereign member verifies a counterparty's DAT through the CLI
  (`agent/community_member/cli.py`); the A2A call path does not verify one
  automatically.
- **Operational grants** (org side): an operator's bounded approval — every
  bound mandatory, consumed at the moment of the side effect
  (`server/bounded_grants.py`; `server/tests/test_bounded_grants.py::test_a_grant_without_a_cap_is_refused`).
  A retry of the same `action_key` is authorized but not charged
  (`::test_a_retry_of_the_same_action_is_authorized_but_not_charged`).
- **Consent decisions** (agent side): the gate's verdict on one proposal,
  as a ledger row and an sm-aae envelope (`agent/community_member/consent/aae_emit.py`).
  Refusals are recorded too — "we said no" is a signed artifact, not an
  absence.

**What it proves.** That at the recorded time the named party was allowed
(or refused) the named scope.

**What it does not prove.** That the action was performed, performed once,
or performed within the scope. A consumed grant and a signed `authorized`
envelope are both consistent with a runner that then crashed.

**Who can check it.** Only the producer's own libraries. The DAT is verified
by the vendored verifier (`agent/community_member/_dat/`) and the envelope by
`sm_aae`; **no verifier of either exists in this tree that is separate from
the code that produced them**, unlike a receipt, which two independent
JavaScript verifiers in `smb_funnel/` check from a card's `did:key`. A third
party holding a DAT or an envelope can re-run the producer's checks, and that
is all. The delegated-call path exports both beside the receipt so this limit
is visible in the evidence rather than hidden by it
(`agent/community_member/delegated_call.py::call_under_authority`).

### 2.3 A counterparty acknowledgement — a co-signature

**What it is.** The counterparty of an A2A interaction signs the issuer's
*unsigned* receipt over the `nanda/cosignReceipt` RPC, and the entry is
inserted before the issuer signs, so the issuer's signature covers it
(`agent/community_member/cosign.py::make_witness`, `::attach_entry`;
`agent/tests/test_cosign.py::test_record_interaction_corroborated_and_signed`).
The witness signs only if it is the **named, distinct** counterparty
(`::test_make_witness_declines_third_party`, `::test_make_witness_declines_self_corroboration`).
A decline, an unreachable counterparty or a bad signature yields a valid but
uncorroborated receipt, never an error (`::test_attach_forged_signature_rolled_back`).

**What it proves.** That the counterparty saw this receipt and was willing to
be named on it. Under `nanda-rep/0.2` this is what lets a receipt count
toward reputation at all; a self-attested receipt scores zero
(`server/tests/test_trust_scoring_integrity.py`).

**What it does not prove.** That the interaction's outcome occurred. The
co-signature is collected immediately after `send_task` returns; the witness
attests to the receipt's description of the call, not to the result of the
task it started.

### 2.4 A confirmed external outcome — nothing in the tree produces one today

State this plainly rather than let the vocabulary imply it:

- An A2A task's result is the counterparty's response body. It is not
  signed by the counterparty (the co-signature covers the receipt, not the
  response), and nothing checks it against the world.
- A booking's delivery is a webhook response, reported as `delivered` in the
  tool return and not in the receipt (`agent/tests/test_booking_skill.py::test_no_configured_sender_is_reported_not_treated_as_delivered`).
  A booking with an email contact is recorded and receipted and **not
  delivered** — no email sender ships, and the result says so by name.
- An outbound email's `delivered` is the provider's HTTP response, recorded
  after the send (`server/external_send.py::_receipt`).
- No human is notified of any of these by the runtime; there is no
  acknowledgement channel back from a person.

So the strongest statement a verifier can make about an external effect is:
*the issuer signed a claim that it acted, and (when corroborated) the
counterparty acknowledged the claim.* The effect itself is not evidenced.

### 2.5 The window between an action and its record

The receipt for an A2A call is built **after** the call returns
(`agent/community_member/a2a_client_v2.py::send_task_recorded`). Between the
counterparty executing and the receipt landing in the Agency Log, the action
has happened and no record exists. A raise anywhere in that window — the
transport, the co-sign round trip, the log write — records nothing
(`agent/tests/test_interactions.py::test_send_task_recorded_records_nothing_on_failure`).
A timeout after the counterparty already executed lands in the same case.

The category a reader must hold for such an action is **UNKNOWN**: it was
issued, and its outcome was not observed. UNKNOWN is not "did not happen" —
a log with no entry for an action is consistent with both, and today the
Agency Log cannot tell them apart. A reader reconstructing history from the
log must therefore treat the absence of a receipt as *no evidence*, not as
evidence of absence. The booking skill is the one path that already orders
the record before the effect (§1); the A2A path does not.

The same shape exists on the consent side. `execute_plan` invokes the runner
and then tombstones the one-shot approval
(`agent/community_member/executor.py::execute_plan`;
`agent/tests/test_consent_approve_execute.py::test_consumed_approval_does_not_double_fire_next_cycle`
covers the tombstoned case). Between the runner firing and the tombstone
landing, the approval is still valid within its TTL; a crash there leaves an
approval that can re-fire on the next cycle. The retry loop around
`gate.mark_consumed` covers a transient database failure, not that ordering.

---

## 3. Offline freshness limits

What a verifier holding an artifact can conclude **without contacting
anyone**, and what goes stale without the artifact changing.

| Artifact | Verifiable offline | Goes stale silently |
|---|---|---|
| **ARP receipt** | Signature; hash-chain link to the previous receipt; corroboration, from the `did:key`s the receipt names. | **Skill revocation** — a receipt does not carry it. The org's revocation list is checked per high-risk execution with a 24-hour cache (`agent/community_member/revocation.py::check_fresh`; `agent/tests/test_revocation.py::test_R4_revoked_cache_survives_offline`), so a receipt issued by a skill revoked an hour later verifies exactly as before. **Key rotation** — a receipt signed by a rotated-out key stays valid for its time, because `did:key` is self-certifying; nothing in the receipt says the key was later retired. |
| **A member's key rotation** | The rotation attestation is signed by the key being retired (`server/member_rotation.py`; `server/tests/test_member_rotation.py::test_R1_forgery_wrong_signing_key`, `::test_R2_replay_rejected_after_first_success`). | A verifier learns of a **member's** rotation only from the org: the org replaces the key it verifies that member's signed requests with (`server/auth_verify.py`) and records the attested link in `member_key_rotations`. There is no public member rotation chain. The **org's** own rotations are public at `/.well-known/nanda-chapter-rotation.json` (`server/federation_policy.py::published_rotation_chain`), unauthenticated by design because a peer needs it exactly when it can no longer verify the org's signatures. |
| **PARC** (portable reputation credential) | Signature and the behavioral Merkle root over the ledger snapshot it was built from (`agent/community_member/reputation_credential.py::build_self_credential`; `agent/tests/test_reputation_credential.py::test_verify_rejects_tampered_credential`). Selective disclosure proves chosen receipts are under that root without revealing the rest (`agent/community_member/receipt_disclosure.py`; `agent/tests/test_receipt_disclosure.py::test_non_member_receipt_rejected`). | It is **self-issued**, with `valid_from`/`valid_until` set by the issuer (30 days on the served route). The scores derive from the receipts the issuer chose to include; the root commits to that snapshot, not to the ledger's completeness. Nothing in it expires a revoked or rotated signer. |
| **Conformance badge** | Signature over the self-check result; `signed_at` and `completed_at` (`server/conformance_boot.py`; [`VERIFY_A_BADGE.md`](./VERIFY_A_BADGE.md)). | **Age is unbounded.** The badge has no expiry, and boot never regenerates a badge that still verifies, so the served badge can be as old as the first boot. It is self-attested: nobody witnessed the run. |
| **Member listing** (`/.well-known/agent-community-listing.json`) | Nothing cryptographic: the document is unsigned JSON with a `generated_at` (`server/member_listing.py::build`). | **Consent withdrawal** — `POST /api/me/listing` with `listed: false` removes the member from the next build and makes the profile route 404 at once (`server/tests/test_member_listing.py`), but a copy already fetched still lists them and carries no signal that it is stale. |
| **Org checkpoint** (RFC 6962 root over the issuer log) | Signature and inclusion proof (`agent/community_member/checkpoint.py`; `agent/tests/test_checkpoint.py::test_receipt_not_in_tree_rejected`). | A later checkpoint may or may not extend an earlier one; a consistency proof exists in the library (`server/merkle.py::consistency_proof`) but no route serves one. See §4 for where the checkpoint is served at all. |

---

## 4. Checkpoint and fork assumptions

Three commitments exist, at different grains, and none of them is a
transparency log.

**The per-issuer hash chain.** Each receipt links to the previous one by
hash-of-canonical-bytes-including-signature
(`agent/community_member/arp.py::receipt_chain_link`;
`agent/tests/test_interactions_chaining.py`). A verifier holding a run of
receipts detects *mutation or omission inside the run*. It does not detect
**tail truncation** — a shorter chain that stops earlier is a valid chain —
and it does not detect a **fork**: two runs branching from the same
predecessor are each valid on their own. The consent ledger closes the
truncation case for itself with a signed head checkpoint
(`agent/community_member/consent/ledger.py::_check_head_checkpoint`); the
Agency Log has no equivalent, and the AAE chain accepts a correctly-chained
envelope signed by a *different* key under the same `agent_id`
(`agent/tests/consent/test_aae_chain_adversarial.py::test_same_agent_foreign_key_append_is_NOT_detected`
records that boundary as today's behaviour).

**The org's Merkle checkpoint.** The org signs an RFC 6962 root over its
issuer log and serves an inclusion proof per receipt
(`server/arp.py::build_checkpoint`; `server/merkle.py::inclusion_proof`;
`server/tests/test_merkle.py`), and a member can check that its own receipt
is committed under the org's signature without the rest of the log
(`agent/tests/test_checkpoint.py::test_member_receipt_committed_verifies`).
The limit that matters: **both routes are served only when the issuer log is
the local SQLite backend** — `GET /api/checkpoint` and
`GET /api/checkpoint/proof/{receipt_id}` return 404 otherwise
(`server/chapter_agent.py::checkpoint_endpoint`,
`::checkpoint_proof_endpoint`, gated on `server/arp.py::is_offline`). A
member of a Postgres-backed org cannot obtain a checkpoint from it today, so
the member-side verifier has nothing to verify against in that deployment.

**What a member can and cannot detect about its own org.** With receipts and
no checkpoint: mutation of receipts it holds (signature), reordering within a
run it holds (chain), and nothing about what the org's log omits. With a
checkpoint (SQLite-backed org only): that a receipt it holds is committed
under the org's signature. In neither case: that the org serves the same
log to everyone. **An org that forks its own log** — one view for one
audience, another for another — is detectable only by two parties comparing
signed checkpoints, and no route publishes a checkpoint history.

**What the divergence detector catches, and what it cannot.** Signed
endpoint attestations make a single registry's tampering with a record
detectable (`server/registry_attestation.py::verify`;
`server/tests/test_registry_attestation.py`), and a DID pin refuses a
registry that later serves a different identity for a pinned peer
(`server/federation_policy.py::check_and_pin_did`). Neither can prove what a
registry *chose not to serve*. With **two or more** registries configured,
`server/registry_divergence.py` asks each the same by-id question and emits
a finding on disagreement — `omission` (one serves, another confirms absent),
`endpoint`, or `did` (`server/tests/test_registry_divergence.py::test_omission_detected`,
`::test_did_divergence_detected`). An unreachable registry is excluded, not
counted as absence (`::test_unreachable_registry_is_not_omission`). With
**one** registry the detector is a no-op (`::test_single_registry_is_noop`):
a single registry that hides an org, or tells two clients different things,
is not detected by anything in this tree. The first sighting of any peer's
DID is trust-on-first-use (audit finding H1, §6).

---

## 5. Hosted versus owner-controlled custody

Who holds which key, and therefore who can sign as whom.

### 5.1 Sovereign agent (`community-member` on the member's machine)

- The Ed25519 seed lives in a vault under the agent home, never in plaintext
  on disk (`agent/community_member/keystore.py`;
  `agent/tests/test_keystore.py::test_S4_config_save_never_writes_plaintext_key`).
  Three backends: the OS keychain, a user passphrase (PBKDF2, entered
  interactively, never written), or a device fingerprint (hostname + home +
  machine id — survives copying the vault elsewhere, not root on the same
  machine: `::test_R7_fingerprint_change_breaks_decryption`).
- A 24-word recovery phrase derives the same key by SLIP-0010
  (`agent/community_member/recovery.py`;
  `agent/tests/test_wizard_recovery.py::test_signup_identity_is_restorable_from_the_displayed_phrase`).
- **The org never holds the member's key.** Registration sends the public key
  (`POST /api/members`); rotation is authorized by a signature from the old
  key (`server/member_rotation.py`). What the org *can* do to a member's
  identity at the org's own directory: for a member with **no key on file
  and no rotation history**, adopt the first key claimed (`server/chapter_agent.py::_pin_member_key`;
  `server/tests/test_member_key_provenance.py::test_the_first_claim_on_a_keyless_member_is_pinned`,
  `::test_a_pin_never_displaces_a_key_already_on_file`); and at revocation,
  name a successor key as **operator-vouched** — recorded as an assertion to
  review, never as a checked fact (`server/chapter_agent.py::KEY_SOURCE_OPERATOR_VOUCHED`;
  the precedence rotation > vouch > pin is asserted by the same test module).
  Neither lets the operator sign as the member: a vouched or pinned key is a
  different `did:key`, and every receipt the member signed stays verifiable
  under the member's own.
- What the member cannot do to the org: nothing beyond what a signed member
  request is authorized for; the org key is not on the member's machine.

### 5.2 A hosted SMB tenant (`smb_host`)

- The **host process mints the key** — `smb_host/main.py::_provision_tenant`
  calls `agent/community_member/recovery.py::generate_recovery` and stores the
  seed in the tenant's own vault under the host's keystore backend. The
  24-word phrase is returned once in the `POST /provision` response and never
  written by the host ([`smb_host/OPERATIONS.md`](../smb_host/OPERATIONS.md)
  checks every file in a fresh tenant home for it).
- **The operator can act as the business.** The host holds the tenant seed
  in memory whenever it serves (`agent/community_member/tenant.py::AgentContext`,
  `private_key_seed`) and signs every booking receipt with it. Whoever holds
  the host's backend secret — `COMMUNITY_MEMBER_PASSPHRASE` on the
  recommended configuration, or the container's device fingerprint by
  default — can open every tenant vault on the volume. That is the custody
  trade this deployment shape makes, and no code in the tree narrows it.
- **The business holds a recovery phrase and nothing else.** The phrase
  reconstructs the key in a tool that accepts one; the host has no import or
  restore route, so it does not put a business back on this host
  (`smb_host/OPERATIONS.md`).
- Tenants cannot reach each other: every store is under the tenant's own
  home, and the host never touches process-global identity
  (`smb_host/test_isolation_guards.py::test_each_business_is_reached_only_through_its_own_home`,
  `::test_the_host_reaches_no_process_global_identity`).
- The host performs **no consent-gated action** for a tenant — the consent
  ledger is never activated there (`smb_host/main.py`;
  `smb_host/test_isolation_guards.py::test_the_host_never_makes_the_call_that_merges_two_businesses`
  asserts the activating call is absent).

### 5.3 The org

- The org's Ed25519 signing key is stored in Postgres sealed with AES-256-GCM
  under a key derived from `ORRERY_KEY_SECRET` (`server/secret_sealing.py`;
  `server/tests/test_secret_sealing.py::test_sealed_value_needs_the_same_secret`,
  `::test_tamper_is_rejected`). The server refuses to start without the
  secret unless the operator opts out explicitly
  (`::test_sealing_required_by_default`, `::test_explicit_opt_out_is_honoured`).
- Whoever holds **both** the database and `ORRERY_KEY_SECRET` can sign as
  the org: every org receipt, checkpoint, federation broadcast and the
  rotation chain. A database dump alone is ciphertext.
- The org key never leaves the org; members verify it through
  `/.well-known/did.json`, and peers pin it (§4).

---

## 6. What this is not

- **It is not a claim of production security.** Test counts, green gates and
  signed badges show that stated properties hold in the tests that state
  them; they do not show the absence of properties nobody stated. The badge
  says so itself (§3).
- **It is not an independent audit.** Every signature in this tree is
  produced by the party the signature is about, except a counterparty
  co-signature, whose scope is §2.3.
- **The audit's open and residual findings apply to everything above.** They
  are in `docs/audit/findings.json` by id; the ones that bound this page
  directly: **H1** (registration and first DID sighting are
  trust-on-first-use), **H8** (the admin surface ships with no token set),
  **M2** (the replay-nonce store is memory-only — a signed request captured
  inside the window can be replayed after a restart), **M4** (SECURITY
  DEFINER functions), **M9** (no authentication on the local agent API),
  **M18** (A2A interop is exempt from method binding), **M20**, **L5**
  (an ephemeral in-memory key fallback), **L7**, **L10**, **L11** (event
  payload text reaches subscribers unescaped). Their current status is the
  ledger's, not this page's; `scripts/audit_gate.py` holds the two in step.
- **It is not a statement about horizontal scale.** Rate limiting, nonce
  replay and the consent gate are per-process where
  [`CONFIGURATION.md`](./CONFIGURATION.md) says they are.
