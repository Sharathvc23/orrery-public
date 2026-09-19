#!/usr/bin/env bash
#
# Two separately administered agents, one bounded interaction, verified by a
# second implementation — and four ways it refuses.
#
# What this stands up, all on this machine, nothing shared between the sides:
#
#   org one  (Compose, with a database)   ← agent A joins it
#   org two  (Compose, its own identity)  ← agent B joins it
#   agent A  its own home, keystore, passphrase, consent ledger, principal
#   agent B  its own home, keystore, passphrase, consent ledger — and its own
#            A2A gate (signed callers only), its own co-signing key
#
# Then ONE call: A's principal signs a grant naming exactly one action
# (a2a.tasks/send#save_note) for exactly A; A's consent gate records the verdict
# as a signed sm-aae envelope; A calls B over A2A with the attempt written ahead
# of the wire; B executes and co-signs; A's receipt is finalized and pushed to
# org one, which commits it under a signed Merkle checkpoint.
#
# Everything is exported to an evidence directory, and the receipt is verified
# OFFLINE by smb_funnel/verify.mjs (JavaScript, WebCrypto, JCS — no code shared
# with the Python producer) with A's did:key taken from A's agent card, never
# from the receipt. The co-signature is verified the same way by
# smb_funnel/verify_cosign.mjs with B's did:key from B's card.
#
# Then four refusals, each driven for real and each leaving evidence:
#   1. denial      — a grant for a different action, and no grant at all
#   2. tampering   — one byte of the receipt flipped; the issuer did swapped
#   3. expiry      — a grant whose not_after is in the past
#   4. interruption — A is killed the instant B's answer arrives, before A's
#                     receipt is written; A's restart names the UNKNOWN attempt
#                     and a retry with the same id is refused
#
# Usage:
#   bash scripts/demo_two_agents.sh                 # evidence → ./demo-evidence/
#   bash scripts/demo_two_agents.sh --evidence DIR  # somewhere you choose
#   bash scripts/demo_two_agents.sh --keep          # leave the stack + agents up
#
# Needs: Docker with Compose v2, Python 3.10+, Node 20+. Ports are allocated
# (nothing is demanded). Teardown leaves 0 listeners and 0 volumes of its own.
# Exit 0 iff the happy path AND all four refusals came out as stated.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE="$ROOT/demo-evidence"
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --evidence) EVIDENCE="$(mkdir -p "$2" && cd "$2" && pwd)"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

hr()  { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
ok()  { printf '   \033[32m✓\033[0m %s\n' "$1"; }
say() { printf '   %s\n' "$1"; }
die() { printf '   \033[31m✗ %s\033[0m\n' "$1" >&2; exit 1; }

# ── prerequisites ──────────────────────────────────────────────────────────
hr "prerequisites"
command -v docker >/dev/null || die "docker not found"
docker compose version >/dev/null 2>&1 || die "docker compose (v2) not found"
command -v node >/dev/null || die "node not found (20+ needed for WebCrypto Ed25519)"
node -e 'process.exit(parseInt(process.versions.node) >= 20 ? 0 : 1)' || die "node 20+ required, have $(node --version)"
if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; else PY="$(command -v python3)"; fi
[ -n "${PY:-}" ] || die "python3 not found"
# The tree this script sits in is the tree that runs — never a package
# installed from somewhere else.
export PYTHONPATH="$ROOT/agent${PYTHONPATH:+:$PYTHONPATH}"
if ! "$PY" -c "import community_member, sm_arp, sm_aae, httpx, uvicorn" 2>/dev/null; then
  VENV="$ROOT/.orrery-demo-venv"
  if [ ! -x "$VENV/bin/python" ]; then
    say "installing the agent runtime into $VENV (first run only)…"
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q -r "$ROOT/agent/requirements.lock" && "$VENV/bin/pip" install -q -e "$ROOT/agent" --no-deps
  fi
  PY="$VENV/bin/python"
  "$PY" -c "import community_member, sm_arp, sm_aae, httpx, uvicorn" || die "agent runtime does not import from $VENV"
fi
ok "docker compose, node $(node --version), python $("$PY" -c 'import sys;print(".".join(map(str,sys.version_info[:3])))')"

WORK="$(mktemp -d)"
PROJECT="orrery-two-agent-demo"
PIDS=()
cleanup() {
  local rc=$?
  if [ "$KEEP" = 1 ]; then
    say "kept (--keep): compose project $PROJECT, agents ${PIDS[*]:-}, work dir $WORK"
    exit "$rc"
  fi
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && wait "$p" 2>/dev/null || true; done
  (cd "$ROOT" && docker compose -p "$PROJECT" --env-file "$WORK/compose.env" \
      -f docker-compose.yml -f infra/compose.two-orgs.yml down -v --remove-orphans >/dev/null 2>&1) || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

free_port() { "$PY" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }
wait_http() { # url label seconds
  local i; for i in $(seq 1 "$3"); do curl -fsS --noproxy '*' "$1" >/dev/null 2>&1 && return 0; sleep 2; done
  die "$2 never answered at $1"
}
jget() { curl -fsS --noproxy '*' "$1"; }
card_did() { # url → the did:key the agent card publishes (x-nanda.did, else authentication.credentials)
  jget "$1/.well-known/agent.json" | "$PY" -c 'import json,sys; c=json.load(sys.stdin); d=(c.get("x-nanda") or {}).get("did") or (c.get("authentication") or {}).get("credentials") or ""; assert d.startswith("did:key:"), c; print(d)'
}
jq_py() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

# ── 1. two orgs ─────────────────────────────────────────────────────────────
hr "1. two orgs, separately administered"
ORG1_PORT="$(free_port)"; ORG2_PORT="$(free_port)"
cat > "$WORK/compose.env" <<EOF
ORG_ID=org-one
ORG_NAME=Org One
PUBLIC_URL=http://localhost:$ORG1_PORT
SERVER_PORT=$ORG1_PORT
ORG_TWO_ID=org-two
ORG_TWO_NAME=Org Two
ORG_TWO_PORT=$ORG2_PORT
ORRERY_PROFILE=prod
POSTGRES_DB=orrery
POSTGRES_USER=postgres
POSTGRES_PASSWORD=$(openssl rand -hex 24)
APP_DB_PASSWORD=$(openssl rand -hex 24)
ORRERY_KEY_SECRET=$(openssl rand -hex 32)
REGISTRY_URL=
AUTO_REGISTER=false
EOF
GIT_COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
export GIT_COMMIT
say "booting org one on :$ORG1_PORT and org two on :$ORG2_PORT (compose project $PROJECT)…"
(cd "$ROOT" && docker compose -p "$PROJECT" --env-file "$WORK/compose.env" \
    -f docker-compose.yml -f infra/compose.two-orgs.yml up -d --build >"$WORK/compose-up.log" 2>&1) \
  || { tail -30 "$WORK/compose-up.log" >&2; die "compose up failed"; }
ORG1="http://127.0.0.1:$ORG1_PORT"; ORG2="http://127.0.0.1:$ORG2_PORT"
wait_http "$ORG1/health" "org one" 90; wait_http "$ORG2/health" "org two" 90
ORG1_DID="$(jget "$ORG1/agentfacts.json" | jq_py 'd["id"]')"
ORG2_DID="$(jget "$ORG2/agentfacts.json" | jq_py 'd["id"]')"
[ "$ORG1_DID" != "$ORG2_DID" ] || die "the two orgs share an identity"
ok "org one $ORG1_DID"
ok "org two $ORG2_DID (db-less: registers members, records no receipts)"

# ── 2. two agents ───────────────────────────────────────────────────────────
hr "2. two agents, each with its own home, keystore, passphrase and org"
start_agent() { # letter org_url port
  local L="$1" HOME_X="$WORK/agent-$1" PASS_X
  mkdir -p "$HOME_X"; chmod 700 "$HOME_X"
  # The passphrase is minted once per agent and reused on a restart — the
  # keystore it sealed must unlock with the same one, as on any real machine.
  if [ ! -s "$WORK/agent-$L.passphrase" ]; then
    (umask 077; openssl rand -hex 16 | tr -d '\n' > "$WORK/agent-$L.passphrase")
  fi
  PASS_X="$(cat "$WORK/agent-$L.passphrase")"
  AGENT_ID="agent-$L" AGENT_NAME="Agent $(echo "$L" | tr a-z A-Z)" AGENT_SKILLS=general \
  CHAPTER_URL="$2" PORT="$3" BIND_HOST=127.0.0.1 AGENT_PUBLIC_URL="http://127.0.0.1:$3" \
  COMMUNITY_MEMBER_HOME="$HOME_X" COMMUNITY_MEMBER_KEYSTORE=passphrase COMMUNITY_MEMBER_PASSPHRASE="$PASS_X" \
  COMMUNITY_MEMBER_NO_REGISTRY=1 AGENT_PROVIDER= AGENT_API_KEY= \
    "$PY" "$ROOT/agent/serve.py" >>"$WORK/agent-$L.log" 2>&1 &
  PIDS+=("$!")
}
agent_env() { # letter → prints env assignments for CLI use as A
  echo "COMMUNITY_MEMBER_HOME=$WORK/agent-$1 COMMUNITY_MEMBER_KEYSTORE=passphrase COMMUNITY_MEMBER_PASSPHRASE=$(cat "$WORK/agent-$1.passphrase")"
}
A_PORT="$(free_port)"; B_PORT="$(free_port)"
start_agent a "$ORG1" "$A_PORT"; A_PID="${PIDS[-1]}"
start_agent b "$ORG2" "$B_PORT"
A_URL="http://127.0.0.1:$A_PORT"; B_URL="http://127.0.0.1:$B_PORT"
wait_http "$A_URL/.well-known/agent.json" "agent A" 60; wait_http "$B_URL/.well-known/agent.json" "agent B" 60
A_DID="$(card_did "$A_URL")"
B_DID="$(card_did "$B_URL")"
[ "$A_DID" != "$B_DID" ] || die "the two agents share a key"
for i in $(seq 1 30); do
  m1="$(jget "$ORG1/health" | jq_py 'd.get("members",0)')"; m2="$(jget "$ORG2/health" | jq_py 'd.get("members",0)')"
  [ "$m1" -ge 1 ] && [ "$m2" -ge 1 ] && break; sleep 2
done
[ "$m1" -ge 1 ] && [ "$m2" -ge 1 ] || die "agents did not join their orgs (org one members=$m1, org two members=$m2)"
ok "agent A $A_DID — joined org one"
ok "agent B $B_DID — joined org two"
say "A's keystore: $WORK/agent-a (passphrase-sealed); B's: $WORK/agent-b — different homes, different passphrases"

# ── 3. principals and grants ────────────────────────────────────────────────
hr "3. A's principal signs a grant naming exactly one action"
mkdir -p "$WORK/operator-a"; chmod 700 "$WORK/operator-a"
NOT_AFTER="$("$PY" -c 'from datetime import datetime,timedelta,UTC; print((datetime.now(UTC)+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
EXPIRED_AT="$("$PY" -c 'from datetime import datetime,timedelta,UTC; print((datetime.now(UTC)-timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
# The first grant mints A's principal; its phrase goes to the operator's private
# dir (never the evidence dir) and signs the other grants so all name one grantor.
env $(agent_env a) "$PY" -m community_member dat grant --grantee "$A_DID" --tool save_note --not-after "$NOT_AFTER" \
    --summary "A may ask B to save one note" --out "$WORK/operator-a/grant-save_note.json" \
    2>"$WORK/operator-a/grant.stderr" >/dev/null
sed -n 's/^  //p' "$WORK/operator-a/grant.stderr" | head -1 > "$WORK/operator-a/principal.phrase"
chmod 600 "$WORK/operator-a/principal.phrase"; rm -f "$WORK/operator-a/grant.stderr"
PHRASE="$(cat "$WORK/operator-a/principal.phrase")"
[ -n "$PHRASE" ] || die "no principal phrase captured"
COMMUNITY_MEMBER_OWNER_PHRASE="$PHRASE" env $(agent_env a) "$PY" -m community_member dat grant --grantee "$A_DID" --tool install_skill \
    --not-after "$NOT_AFTER" --out "$WORK/operator-a/grant-other-action.json" >/dev/null
COMMUNITY_MEMBER_OWNER_PHRASE="$PHRASE" env $(agent_env a) "$PY" -m community_member dat grant --grantee "$A_DID" --tool save_note \
    --not-before "$EXPIRED_AT" --not-after "$EXPIRED_AT" --out "$WORK/operator-a/grant-expired.json" >/dev/null 2>&1 || true
[ -s "$WORK/operator-a/grant-expired.json" ] || die "could not mint the expired grant"
GRANTOR="$(jq_py 'd["grantor_did"]' < "$WORK/operator-a/grant-save_note.json")"
[ "$GRANTOR" != "$A_DID" ] || die "the principal is the agent's own key"
ok "principal $GRANTOR (not A's key) signed: save_note until $NOT_AFTER; install_skill; save_note expired $EXPIRED_AT"

rm -rf "$EVIDENCE"; mkdir -p "$EVIDENCE"
jget "$A_URL/.well-known/agent.json" > "$EVIDENCE/issuer_card.json"
jget "$B_URL/.well-known/agent.json" > "$EVIDENCE/counterparty_card.json"
A_DID_CARD="$(card_did "$A_URL")"
B_DID_CARD="$(card_did "$B_URL")"

# ── 4. the interaction ──────────────────────────────────────────────────────
hr "4. A calls B (save_note) under the grant; B executes and co-signs"
TASK="demo-$(date +%s)"
set +e
env $(agent_env a) "$PY" -m community_member call --peer "$B_URL" --tool save_note \
    --args '{"key":"from-a","value":"hello from agent A"}' --under "$WORK/operator-a/grant-save_note.json" \
    --evidence "$EVIDENCE/1-happy-path" --task-id "$TASK" | tee "$EVIDENCE/1-happy-path.txt"
rc=${PIPESTATUS[0]}; set -e
[ "$rc" = 0 ] || die "the call under a valid grant did not succeed (exit $rc)"
for f in receipt.json attempt.json acknowledgement.json authorization/dat.json authorization/consent_event.json authorization/aae_envelope.json org/receipt_record.json org/checkpoint.json org/inclusion_proof.json; do
  [ -s "$EVIDENCE/1-happy-path/$f" ] || die "missing evidence: $f"
done
RID="$(jq_py 'd["receipt_id"]' < "$EVIDENCE/1-happy-path/receipt.json")"
jq_py 'd["outcome"]' < "$EVIDENCE/1-happy-path/authorization/aae_envelope.json" | grep -qx authorized || die "AAE envelope is not 'authorized'"
jq_py 'd["evidence"]["witness_signatures"][0]["witness_did"]' < "$EVIDENCE/1-happy-path/receipt.json" | grep -qx "$B_DID_CARD" || die "receipt is not co-signed by B"
jq_py 'd.get("receipt_id")' < "$EVIDENCE/1-happy-path/org/receipt_record.json" | grep -qx "$RID" || die "org one does not hold the receipt (signed read)"
ok "receipt $RID co-signed by B; org one holds it (its signed principal-scoped read returns it)"
if jq_py '"proof" in d' < "$EVIDENCE/1-happy-path/org/inclusion_proof.json" | grep -qx True; then
  CHECKPOINTED=1; ok "org one also serves a signed Merkle checkpoint and an inclusion proof for it"
else
  CHECKPOINTED=0; say "org one is database-backed: it serves no Merkle checkpoint (the server serves one only over a local SQLite Issuer Log) — recorded as 'unavailable' in org/checkpoint.json"
fi

# ── 5. verification by a separate implementation ────────────────────────────
hr "5. verify OFFLINE with smb_funnel/verify.mjs — issuer did:key from A's CARD, not the receipt"
set +e
node "$ROOT/smb_funnel/verify.mjs" --issuer "$A_DID_CARD" "$EVIDENCE/1-happy-path/receipt.json" | tee "$EVIDENCE/1-happy-path/verify.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 0 ] || die "verify.mjs did not accept the receipt under the card's issuer (exit $rc)"
ok "verify.mjs exit 0 — checks: schema, Ed25519 over the JCS-canonical receipt under issuer_did, issuer_did == the card's did"
say "verify.mjs does NOT check: the co-signature, the DAT/authority, chain position, revocation"
set +e
node "$ROOT/smb_funnel/verify_cosign.mjs" --witness "$B_DID_CARD" "$EVIDENCE/1-happy-path/receipt.json" | tee "$EVIDENCE/1-happy-path/verify_cosign.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 0 ] || die "verify_cosign.mjs did not accept B's co-signature (exit $rc)"
ok "verify_cosign.mjs exit 0 — B's Ed25519 co-signature over the corroboration payload, witness did:key from B's card"
if [ "$CHECKPOINTED" = 1 ]; then
  set +e
  env $(agent_env a) "$PY" -m community_member checkpoint verify --receipt "$EVIDENCE/1-happy-path/receipt.json" \
      --checkpoint "$EVIDENCE/1-happy-path/org/checkpoint.json" --proof "$EVIDENCE/1-happy-path/org/inclusion_proof.json" \
      | tee "$EVIDENCE/1-happy-path/checkpoint_verify.txt"; rc=${PIPESTATUS[0]}
  set -e
  [ "$rc" = 0 ] || die "the org's inclusion proof did not verify (exit $rc)"
  ok "inclusion under org one's signed checkpoint verifies (member-side Python verifier; no second implementation exists for this)"
fi
say "the DAT and the AAE envelope have no non-producer verifier in this tree; their signatures are checked by the producer's libraries only"

# ── 6. refusals ─────────────────────────────────────────────────────────────
hr "6.1 DENIAL — a grant for a different action; then no grant at all"
set +e
env $(agent_env a) "$PY" -m community_member call --peer "$B_URL" --tool save_note --args '{"key":"x","value":"y"}' \
    --under "$WORK/operator-a/grant-other-action.json" --evidence "$EVIDENCE/2-denial/other-action" --task-id "$TASK-denied-1" \
    | tee "$EVIDENCE/2-denial-other-action.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 2 ] || die "a grant for another action was not refused at the gate (exit $rc)"
jq_py 'd["verdict"]["stage"]' < "$EVIDENCE/2-denial/other-action/decision.json" | grep -qx scope || die "refusal did not name scope"
jq_py 'd["outcome"]' < "$EVIDENCE/2-denial/other-action/authorization/aae_envelope.json" | grep -qx denied || die "AAE envelope is not 'denied'"
[ ! -e "$EVIDENCE/2-denial/other-action/receipt.json" ] || die "a refused call produced a receipt"
echo '{}' > "$WORK/no-grant.json"
set +e
env $(agent_env a) "$PY" -m community_member call --peer "$B_URL" --tool save_note --args '{"key":"x","value":"y"}' \
    --under "$WORK/no-grant.json" --evidence "$EVIDENCE/2-denial/no-grant" --task-id "$TASK-denied-2" \
    | tee "$EVIDENCE/2-denial-no-grant.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 2 ] || die "a call with no grant was not refused (exit $rc)"
b_saw() { # task id → "seen"|"unseen" via B's OPEN tasks/get
  local r; r="$(curl -s --noproxy '*' -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":\"q\",\"method\":\"tasks/get\",\"params\":{\"id\":\"$1\"}}" "$B_URL/")"
  echo "$r" | grep -q '"error"' && echo unseen || echo seen
}
[ "$(b_saw "$TASK-denied-1")" = unseen ] && [ "$(b_saw "$TASK-denied-2")" = unseen ] || die "B saw a refused task"
ok "both refused at A's gate (exit 2), AAE outcome 'denied', no receipt, B never saw either task id"

hr "6.2 TAMPERING — one byte flipped; then the issuer did swapped to B's key"
mkdir -p "$EVIDENCE/3-tampering"
"$PY" - "$EVIDENCE/1-happy-path/receipt.json" "$EVIDENCE/3-tampering" "$B_DID_CARD" <<'PY'
import json, sys
src, out, other = sys.argv[1], sys.argv[2], sys.argv[3]
r = json.load(open(src))
t = json.loads(json.dumps(r)); s = t["action"]["human_summary"]; t["action"]["human_summary"] = (s[:-1] + ("!" if s[-1] != "!" else "?")) if s else "!"
json.dump(t, open(f"{out}/receipt-byte-flipped.json", "w"), indent=2, sort_keys=True)
u = json.loads(json.dumps(r)); u["issuer_did"] = other
json.dump(u, open(f"{out}/receipt-issuer-swapped.json", "w"), indent=2, sort_keys=True)
PY
set +e
node "$ROOT/smb_funnel/verify.mjs" --issuer "$A_DID_CARD" "$EVIDENCE/3-tampering/receipt-byte-flipped.json" | tee "$EVIDENCE/3-tampering/verify-byte-flipped.txt"; rc1=${PIPESTATUS[0]}
node "$ROOT/smb_funnel/verify.mjs" --issuer "$A_DID_CARD" "$EVIDENCE/3-tampering/receipt-issuer-swapped.json" | tee "$EVIDENCE/3-tampering/verify-issuer-swapped.txt"; rc2=${PIPESTATUS[0]}
node "$ROOT/smb_funnel/verify_cosign.mjs" --witness "$B_DID_CARD" "$EVIDENCE/3-tampering/receipt-byte-flipped.json" | tee "$EVIDENCE/3-tampering/verify_cosign-byte-flipped.txt"; rc3=${PIPESTATUS[0]}
set -e
[ "$rc1" = 1 ] && grep -q "stage=signature" "$EVIDENCE/3-tampering/verify-byte-flipped.txt" || die "byte-flipped receipt not rejected at the signature stage (exit $rc1)"
[ "$rc2" = 1 ] && grep -q "stage=signature" "$EVIDENCE/3-tampering/verify-issuer-swapped.txt" || die "issuer-swapped receipt not rejected at the signature stage (exit $rc2)"
[ "$rc3" = 1 ] || die "byte-flipped receipt's co-signature not rejected (exit $rc3)"
ok "verify.mjs: FAILED stage=signature for both (exit 1); verify_cosign.mjs: FAILED for the flipped byte (exit 1)"

hr "6.3 EXPIRED AUTHORITY — a grant past its not_after"
set +e
env $(agent_env a) "$PY" -m community_member call --peer "$B_URL" --tool save_note --args '{"key":"x","value":"y"}' \
    --under "$WORK/operator-a/grant-expired.json" --evidence "$EVIDENCE/4-expired" --task-id "$TASK-expired" \
    | tee "$EVIDENCE/4-expired.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 2 ] || die "an expired grant was not refused (exit $rc)"
jq_py 'd["verdict"]["stage"]' < "$EVIDENCE/4-expired/decision.json" | grep -qx expired || die "refusal did not name expiry"
grep -q "expired at $EXPIRED_AT" "$EVIDENCE/4-expired.txt" || die "refusal did not name the expiry instant"
[ "$(b_saw "$TASK-expired")" = unseen ] || die "B saw the expired-authority task"
ok "refused at A's gate naming expiry ('expired at $EXPIRED_AT'), AAE outcome 'denied', B never saw it"

hr "6.4 INTERRUPTED EXECUTION — A dies the instant B's answer arrives, before A's receipt is written"
mkdir -p "$EVIDENCE/5-interrupted"
ITASK="$TASK-interrupted"
set +e
env $(agent_env a) "$PY" - "$B_URL" "$WORK/operator-a/grant-save_note.json" "$EVIDENCE/5-interrupted/call" "$ITASK" <<'PY' > "$EVIDENCE/5-interrupted/killed-run.txt" 2>&1
# Fault injection in the DRIVER, not the runtime: the very technique the
# runtime's own tests use. The call returns from the wire — B has executed —
# and the process is killed before send_task_recorded can write anything more.
import json, os, sys
from pathlib import Path
from community_member import delegated_call
from community_member.a2a_client_v2 import GoogleA2AClient
from community_member.config import Config
_real = GoogleA2AClient._rpc
def _rpc_then_die(self, method, params):
    result = _real(self, method, params)
    if method == "tasks/send":
        print(f"[fault] tasks/send returned ({result.get('status', {}).get('state')}); killing A now (os._exit 9)", flush=True)
        os._exit(9)
    return result
GoogleA2AClient._rpc = _rpc_then_die
peer, grant, evidence, task = sys.argv[1:5]
delegated_call.call_under_authority(Config.load(), peer_url=peer, tool="save_note", args={"key": "interrupted", "value": "B did this"},
                                    dat=json.load(open(grant)), evidence_dir=Path(evidence), task_id=task)
print("UNREACHABLE")
PY
rc=$?; set -e
cat "$EVIDENCE/5-interrupted/killed-run.txt"
[ "$rc" = 9 ] || die "the child did not die at the injected point (exit $rc)"
! grep -q UNREACHABLE "$EVIDENCE/5-interrupted/killed-run.txt" || die "the child ran past the kill point"
[ "$(b_saw "$ITASK")" = seen ] || die "B did not execute the interrupted task"
[ ! -e "$EVIDENCE/5-interrupted/call/receipt.json" ] || die "a receipt exists for the interrupted call"
ok "B executed $ITASK (tasks/get answers); A has no receipt for it"
say "restarting A…"
kill "$A_PID"; wait "$A_PID" 2>/dev/null || true
: > "$WORK/agent-a.log"
start_agent a "$ORG1" "$A_PORT"; A_PID="${PIDS[-1]}"
wait_http "$A_URL/.well-known/agent.json" "agent A (restarted)" 60
grep "\[agency-log\]\[UNKNOWN\]" "$WORK/agent-a.log" | tee "$EVIDENCE/5-interrupted/restart-log.txt" >/dev/null
grep -q "\[agency-log\]\[UNKNOWN\]" "$EVIDENCE/5-interrupted/restart-log.txt" || die "A's restart did not name the unresolved attempt"
TOKEN="$(cat "$WORK/agent-a/.local-token")"
curl -fsS --noproxy '*' -H "Authorization: Bearer $TOKEN" "$A_URL/api/agency-log/unresolved" > "$EVIDENCE/5-interrupted/unresolved.json"
jq_py "any(a.get('action_ref')=='$ITASK' and a.get('state')=='unknown' for a in (d if isinstance(d,list) else d.get('attempts', d.get('unresolved', []))))" \
    < "$EVIDENCE/5-interrupted/unresolved.json" | grep -qx True || die "the interrupted attempt is not listed as unknown"
set +e
env $(agent_env a) "$PY" -m community_member call --peer "$B_URL" --tool save_note --args '{"key":"interrupted","value":"B did this"}' \
    --under "$WORK/operator-a/grant-save_note.json" --evidence "$EVIDENCE/5-interrupted/retry" --task-id "$ITASK" \
    | tee "$EVIDENCE/5-interrupted-retry.txt"; rc=${PIPESTATUS[0]}
set -e
[ "$rc" = 3 ] || die "a retry of the unknown-outcome action was not refused (exit $rc)"
ok "on restart A logs the attempt as UNKNOWN, lists it under /api/agency-log/unresolved, claims no success, and refuses the retry (exit 3)"

# ── done ────────────────────────────────────────────────────────────────────
hr "DONE"
cat > "$EVIDENCE/README.txt" <<EOF
Two-agent demo evidence — produced by scripts/demo_two_agents.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ), tree $GIT_COMMIT

issuer_card.json / counterparty_card.json   A's and B's agent cards; the did:key values the verifiers were given
1-happy-path/receipt.json                    A's ARP receipt, co-signed by B (evidence.witness_signatures)
1-happy-path/attempt.json                    the Agency Log attempt written BEFORE the call, finalized after
1-happy-path/acknowledgement.json            B's A2A task result
1-happy-path/authorization/dat.json          the grant A's principal signed (one action, one grantee, a window)
1-happy-path/authorization/consent_event.json  A's consent-ledger row for the verdict
1-happy-path/authorization/aae_envelope.json   the signed sm-aae envelope (outcome: authorized)
1-happy-path/org/receipt_record.json         org one's own copy of the receipt (its signed, principal-scoped read)
1-happy-path/org/checkpoint.json             org one's signed Merkle checkpoint — or {"unavailable": ...}: a
1-happy-path/org/inclusion_proof.json          database-backed org serves none (SQLite-backed orgs do)
1-happy-path.txt                             what community-member call printed
1-happy-path/verify.txt                      smb_funnel/verify.mjs output (issuer from the card)
1-happy-path/verify_cosign.txt               smb_funnel/verify_cosign.mjs output (witness from the card)
2-denial/                                    refused: different action (stage scope); no grant at all
3-tampering/                                 byte flipped / issuer swapped → verify.mjs FAILED stage=signature
4-expired/                                   refused: stage expired, naming not_after
5-interrupted/                               A killed after B answered: no receipt, UNKNOWN on restart, retry refused
EOF
ok "evidence → $EVIDENCE"
say "orgs: $ORG1 ($ORG1_DID), $ORG2 ($ORG2_DID); agents: A $A_DID_CARD, B $B_DID_CARD; tree $GIT_COMMIT"
