#!/usr/bin/env bash
#
# SMB full-stack dress rehearsal — the live demo, end to end, one command.
#
# Boots the REAL pre-warmed multi-tenant host and drives the exact loop the funnel
# performs, verifying the receipt with the funnel's OWN JS verifier
# (smb_funnel/verify.mjs):
#
#   provision (from the warm pool, ~instant) -> live agent card -> book ->
#   receipt verified OFFLINE in the client -> tamper rejected
#
# NOTE: this host registers on NO index. There is one NANDA Index
# (api.nandaindex.org) and registering the provisioned agent there is host39's
# step — out of scope here. This demo covers only what the host does: mint an
# identity, serve the card, and issue verifiable booking receipts.
#
# Everything is throwaway (temp host data dir) and torn down on exit. No
# production writes. Serve smb_funnel at API_BASE=<host> for the visual.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Prefer the repo venv when present (local dev); fall back to whatever is on
# PATH (CI installs into the runner's interpreter, which has no .venv). Without
# this the script is unrunnable in CI, which is why the SMB path had no gate.
if [ -x "$ROOT/.venv/bin/python" ]; then
    PY="$ROOT/.venv/bin/python"
    CM="$ROOT/.venv/bin/community-member"
    UVICORN="$ROOT/.venv/bin/uvicorn"
else
    PY="$(command -v python3)"
    CM="$(command -v community-member)"
    UVICORN="$(command -v uvicorn)"
fi
[ -x "$PY" ] || { echo "no python3 found"; exit 1; }
HOST_PORT="${HOST_PORT:-9712}"
HOST="http://127.0.0.1:${HOST_PORT}"
TMP="$(mktemp -d)"; HOST_PID=""
# The host writes into $TMP/host for as long as it is alive, so removing the
# tree before it has actually exited races it: rm empties the directory, the
# host writes one more file, and the final rmdir fails "Directory not empty".
# And because the EXIT trap's last command sets the script's exit status, that
# failed rm reported a red run whose assertions had all passed. Wait for the
# host to be gone before removing, and return the status the script arrived
# with rather than the teardown's.
cleanup(){
    local rc=$?
    if [ -n "$HOST_PID" ]; then
        kill "$HOST_PID" 2>/dev/null || true
        for _ in $(seq 1 50); do kill -0 "$HOST_PID" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$HOST_PID" 2>/dev/null || true
        wait "$HOST_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP" 2>/dev/null || printf 'warning: could not remove %s\n' "$TMP" >&2
    exit "$rc"
}
trap cleanup EXIT
hr(){ printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
ok(){ printf '   \033[32m✓\033[0m %s\n' "$1"; }
die(){ printf '   \033[31m✗ %s\033[0m\n' "$1"; exit 1; }

hr "0. boot pre-warmed SMB host (pool=3) — no index, registers nowhere"
( cd "$ROOT/smb_host" && HOST_PUBLIC_URL="$HOST" SMB_HOST_DATA_DIR="$TMP/host" \
    SMB_HOST_POOL_SIZE=3 SMB_HOST_TENANT_CAP=1000 COMMUNITY_MEMBER_KEYSTORE=device \
    exec "$UVICORN" main:create_app --factory --port "$HOST_PORT" --log-level warning ) & HOST_PID=$!
for _ in $(seq 1 60); do curl -fsS "$HOST/health" >/dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "$HOST/health" >/dev/null 2>&1 || die "smb host did not come up"
for _ in $(seq 1 80); do [ "$(curl -fsS "$HOST/health" | "$PY" -c 'import json,sys;print(json.load(sys.stdin).get("pool_ready",0))')" -ge 1 ] && break; sleep 0.5; done
ok "SMB host @ $HOST · pool_ready=$(curl -fsS "$HOST/health" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["pool_ready"])')"

hr "1. a barber signs up — POST /provision (served from the warm pool)"
T0=$(date +%s%N)
PROV=$(curl -fsS -X POST "$HOST/provision" -H 'content-type: application/json' -d '{"business_name":"Sharp Cuts Barber","service_type":"barber","contact":"https://bookings.invalid/demo"}') || die "provision failed"
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
TENANT=$(echo "$PROV" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["tenant_id"])')
DID=$(echo "$PROV" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["did"])')
ENDPOINT=$(echo "$PROV" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["endpoint"])')
ok "provisioned '$TENANT' in ${MS}ms  ·  did=${DID:0:40}…  ·  endpoint=$ENDPOINT"
ok "provision response is the host39 handoff: {tenant_id, endpoint, did, recovery_phrase} (no urn)"

hr "2. it serves a live agent card at its endpoint (same did:key)"
CARD=$(curl -fsS "$HOST/t/$TENANT/.well-known/agent.json") || die "agent card not served"
echo "$CARD" | "$PY" -c 'import json,sys;d=json.load(sys.stdin);print("   ✓ live agent card:",d.get("name"),"·",(d.get("authentication") or {}).get("credentials","")[:40],"…")'
# The card is the customer's trust anchor for step 4: the key comes from the
# business's published card, NOT from the receipt being checked.
CARD_DID=$(echo "$CARD" | "$PY" -c 'import json,sys;print((json.load(sys.stdin).get("authentication") or {}).get("credentials",""))')
[ -n "$CARD_DID" ] || die "the agent card publishes no did:key to verify receipts against"

hr "3. a customer books — POST /t/<tenant>/book"
BOOK=$(curl -fsS -X POST "$HOST/t/$TENANT/book" -H 'content-type: application/json' \
  -d '{"service":"Haircut","provider":"Sharp Cuts Barber","datetime":"2026-08-01T15:00:00Z","notes":"walk-in"}') || die "book failed"
echo "$BOOK" > "$TMP/book.json"
"$PY" - "$TMP/book.json" "$TMP/receipt.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); b = d["booking"]
print("   ✓ booked:", b["service"], "· status=" + b["status"], "· receipt", d["receipt_id"][:8] + "…")
json.dump(d["receipt"], open(sys.argv[2], "w"))
PY

hr "4. the customer verifies the receipt OFFLINE in the client (funnel's own JS)"
# --issuer is required: without it the verifier can only say the receipt is
# internally consistent, which a forged receipt signed by its own fresh key also
# is. The did comes from the card fetched in step 2 — a source that is not the
# receipt — so this checks the receipt came from THIS business.
node "$ROOT/smb_funnel/verify.mjs" --issuer "$CARD_DID" "$TMP/receipt.json" | sed 's/^/   /' || die "client verify FAILED on a valid receipt"
"$PY" -c "import json;p='$TMP/receipt.json';d=json.load(open(p));d['action']['human_summary']='TAMPERED';json.dump(d,open(p,'w'))"
# ⚠️ WHAT THE OPERATOR IS TOLD, NOT ONLY THAT THE EXIT WAS NON-ZERO. This line
# read `>/dev/null 2>&1 && die || ok` and passed for months while the verifier
# printed "the signature is valid, but no --issuer was given" for this very file
# and exited 3 — the code that means nobody checked. The exit was non-zero, so
# the assertion was satisfied by the wrong outcome. A verifier's output IS its
# product; a check that discards it is checking that something happened.
TAMPER_OUT=$(node "$ROOT/smb_funnel/verify.mjs" --issuer "$CARD_DID" "$TMP/receipt.json" 2>&1) && die "tampered receipt was ACCEPTED (bug)"
case "$TAMPER_OUT" in
  FAILED*) ok "tampered receipt rejected by the client verifier, and reported as FAILED" ;;
  *) die "tampered receipt was refused but MISREPORTED: $TAMPER_OUT" ;;
esac

# A receipt that is perfectly valid but issued by a DIFFERENT agent must not pass
# as this business's. That is the whole point of anchoring on the published card,
# and without this line the step above would still pass if --issuer were ignored.
OTHER_DID=$(curl -fsS -X POST "$HOST/provision" -H 'content-type: application/json' \
  -d '{"business_name":"Someone Else Entirely","contact":"https://bookings.invalid/demo"}' | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["did"])') || die "second provision failed"
echo "$BOOK" | "$PY" -c "import json,sys;json.dump(json.load(sys.stdin)['receipt'],open('$TMP/receipt.json','w'))"
# Same discipline: this receipt's signature is GOOD and only its identity is
# wrong, so the tool must say MISMATCH. Reporting it as a failed signature would
# send an operator hunting a corrupted file.
OTHER_OUT=$(node "$ROOT/smb_funnel/verify.mjs" --issuer "$OTHER_DID" "$TMP/receipt.json" 2>&1) \
  && die "a receipt from another agent was accepted as this business's (bug)"
case "$OTHER_OUT" in
  MISMATCH*) ok "a valid receipt from a DIFFERENT agent is refused, and reported as MISMATCH" ;;
  *) die "a receipt from another agent was refused but MISREPORTED: $OTHER_OUT" ;;
esac

hr "DONE — the live SMB loop works end to end, on the real host, no prod writes"
printf "   sign up → live card → book → verify offline in-client. No index involved.\n"
printf "   Registering the agent on NANDA (api.nandaindex.org) is host39's next step, out of scope here.\n"
printf "   For the visual: serve smb_funnel with API_BASE=%s and click through it.\n\n" "$HOST"
