# Agent-SDK claims → evidence

Every advertised capability of the sovereign agent runtime (`agent/`, package
`community_member/`), driven end-to-end against **real processes with real
Ed25519 signing** — the org server is `server/chapter_agent.py` in its
in-memory mode; members are real `serve.py` processes; only the LLM is a
deterministic stub so the planner→gate→executor path runs without a model.

Run the live drives:

```bash
# server venv satisfies server/requirements.lock; agent venv runs pytest
ORRERY_E2E=1 ORRERY_SERVER_PYTHON=<server-venv>/bin/python \
    .venv/bin/python -m pytest tests/e2e -q -rA
```

Bare `pytest tests/e2e` skips everything (CI-safety); the adversarial unit
tests (`tests/test_portable.py`, `tests/consent/test_aae_chain_adversarial.py`,
`tests/consent/test_ledger_external_verify.py`) run in the normal suite.

## Claims proven by test

| # | Claim (source) | Evidence |
|---|---|---|
| 1 | Sovereign Ed25519 identity served as a did:key; key never leaves the box (README.md:3-5, QUICKSTART.md:69-73) | `tests/e2e/test_identity_restart.py::test_keypair_persists_across_restart`, `test_join_and_surfaces.py::test_five_nanda_surfaces_bind_one_did` |
| 2 | Identity + keypair persist across restart; a fresh HOME mints a new identity (serve.py:13-18) | `test_identity_restart.py` (both tests): same HOME → same did:key + signed org call still verifies; new HOME → new did:key |
| 3 | Cryptographic membership — join over signed ed25519+nonce; TOFU with `key_mismatch` on a key swap (QUICKSTART.md:69-73) | `test_join_and_surfaces.py::test_join_tofu_and_key_mismatch`, `::test_member_publicly_visible` |
| 4 | The 5 NANDA surfaces on ONE did:key: `/agentfacts.json`, `/.well-known/agent.json` (x-nanda), `/.well-known/conformance.json`, `/.well-known/reputation.json`, `POST /` A2A JSON-RPC (docs/STACK.md:106-108) | `test_join_and_surfaces.py::test_five_nanda_surfaces_bind_one_did` |
| 5 | The advertised 60-second quickstart works verbatim (QUICKSTART.md) | `test_join_and_surfaces.py::test_quickstart_arc_verbatim` |
| 6 | Skills run under a consent gate: propose → prompt → approve → execute now (README.md:51-54, server.py consent-approve) | `test_consent_ladder_e2e.py::test_prompt_approve_execute` |
| 7 | Untrusted provenance is rejected outright, never promptable — the prompt-injection defense (gate.py S3) | `test_consent_ladder_e2e.py::test_untrusted_provenance_rejected_never_promptable` |
| 8 | Deny is first-class with a cooldown (suppression), clearable (STELLARMINDS.md:234-236) | `test_consent_ladder_e2e.py::test_deny_suppression_and_clear` |
| 9 | Graduation ladder (W4): ≥5 approvals auto-approve a bucket live, without a prompt; revoke returns it to prompting; `skill.invoke` never auto-approves | `test_consent_ladder_e2e.py::test_graduation_auto_approve_and_revoke`, `::test_skill_invoke_never_auto_approves`; unit `tests/graduation/test_auto_approval.py` |
| 10 | ARP receipts auto-emitted on A2A calls; cosign makes them corroborated; only corroborated build nanda-rep/0.2 (cosign example, STELLARMINDS.md:44) | `test_arp_cosign_e2e.py` (all 3): example verbatim (loopback + `--chapter`), live member witnesses/declines correctly |
| 11 | Selective disclosure that change: reveal k receipts with sm-parc Merkle proofs; verifies fully offline; tamper fails (STELLARMINDS.md:48) | `test_disclosure_aae_e2e.py::test_disclosure_bundle_verifies_offline_and_tamper_fails` |
| 12 | AAE that change: every gate decision is a signed, per-agent hash-chained envelope; `/api/local/aae/audit` checkpoint commits a sha256-concat root; per-leaf proofs fold offline (STELLARMINDS.md:50,254-262) | `test_disclosure_aae_e2e.py::test_aae_chain_exports_and_folds_offline`; unit `tests/consent/test_aae_chain_adversarial.py` |
| 13 | The sm-* dependency stack is actually installed (green-means-green) | `test_deps_present.py` (hard import, never skip) |

## Claims that were broken/drifted → filed + fixed

| # | Finding | Issue | Fix + regression test |
|---|---|---|---|
| F1 | Safety-doc drift: `consent/gate.py`, `graduation/__init__.py`, `graduation/state.py` claimed auto-approve is "unreachable / everything still prompts", but `executor.py` ships W4 auto-approve of graduated actions | that change | Docstrings corrected to the shipped W4 behavior; behavior pinned by `test_consent_ladder_e2e.py::test_graduation_auto_approve_and_revoke` (live) |
| F2 | `portable.py` (full-state bundle incl. the Ed25519 **private key** + consent/habits/graduations DBs) had ZERO tests | that change | `tests/test_portable.py` (5 tests): round-trip fidelity, `format_version` rejection, api_key never in bundle, restored files 0600, S10 cross-identity non-inheritance |
| F3 | `aae_emit.verify_chain` advertises gap/fork/splice/duplicate detection; only happy+1-tamper were tested. Also found: no per-agent **key pinning** across the chain (a same-`agent_id`, differently-keyed, correctly-chained append is accepted) | that change | `tests/consent/test_aae_chain_adversarial.py` (6 tests): gap/fork/duplicate + cross-agent splice all detected; key-pinning boundary documented as an explicit (currently-passing) test so a future fix flips it deliberately |
| F4 | `ledger.export_jsonl`'s "external verifier re-derives the chain" claim was never behaviorally tested | that change | `tests/consent/test_ledger_external_verify.py` (3 tests): an independent verifier re-derives the chain from JSONL alone; tampered line + dropped line both break |
| F5 | `arp_surfaces.py` docstring pointed at a nonexistent `chapter/surfaces.py` (real: `server/surfaces.py`) and implied a chronicle builder the module doesn't have | that change | Docstring corrected: right path, scope narrowed to the today surface |

## Server-owned (reported, not edited)

None required so far — all findings were in the agent runtime. A cross-surface
issue is filed against the server, not edited under `server/` from here.
