#!/usr/bin/env bash
#
# SMB loop demo — the Milestone-A "it actually works" floor, fully self-contained.
#
# Proves, end to end and OFFLINE-verifiable, with NO production writes:
#   1. express onboard   — a non-technical SMB agent stood up headless (no prompts, keyless)
#   2. operate           — the agent takes a booking, emitting a signed ARP receipt
#   3. proof             — the receipt verifies with the server off; a tampered one is rejected
#
# No index is involved anywhere. There is one NANDA Index (api.nandaindex.org) and
# registering an agent there is host39's job — out of scope for this runtime, which
# only mints an identity and issues verifiable receipts. Everything runs against a
# throwaway home, torn down on exit. Nothing touches the live mesh or any Index.
#
# Usage:  bash scripts/demo_smb_loop.sh
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

TMP="$(mktemp -d)"
export COMMUNITY_MEMBER_HOME="$TMP/.cm"
export COMMUNITY_MEMBER_KEYSTORE="device"
export DISPLAY=""

# The EXIT trap's last command sets the script's exit status, so a teardown
# that fails turns a passing run red. Return the status the script arrived with.
cleanup() {
    local rc=$?
    rm -rf "$TMP" 2>/dev/null || printf 'warning: could not remove %s\n' "$TMP" >&2
    exit "$rc"
}
trap cleanup EXIT

hr() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
ok() { printf '   \033[32m✓\033[0m %s\n' "$1"; }
die() { printf '   \033[31m✗ %s\033[0m\n' "$1"; exit 1; }

# ── 1. express onboard: a headless, keyless SMB agent ────────────────────────────
hr "1. express onboard an SMB agent (headless, no prompts)"
"$CM" init --express --name "Sharp Cuts Barber" 2>&1 \
  | grep -iE "agent_id|did:key" | sed 's/^/   /' || true
ok "sovereign agent minted (did:key) — ready to register on NANDA via host39 (out of scope here)"

# ── 2. operate: take a booking → signed receipt ──────────────────────────────────
hr "2. operate — take a booking (emits a signed receipt)"
RID="$(PYTHONPATH="$ROOT/agent" "$PY" - <<'PY'
import json
from pathlib import Path
from community_member import arp, skill_runtime as sr
from community_member.config import CONFIG_DIR
tool = next(s for s in sr.load_builtin_skills() if s.name == "booking").tools["book_appointment"]
out = tool({"service": "Haircut", "provider": "Sharp Cuts", "datetime": "2026-08-01T15:00", "notes": "walk-in"})
rid = out["receipt_id"]
rec = arp.AgencyLog(CONFIG_DIR).get(rid)
Path(f"{CONFIG_DIR}/receipt.json").write_text(json.dumps(rec, indent=2))
print(rid)
PY
)"
ok "booked; signed receipt $RID"

# ── 3. proof: verify offline, then prove tampering is caught ─────────────────────
hr "3. proof — verify the receipt OFFLINE (server is not even in the path)"
if "$CM" receipt verify "$COMMUNITY_MEMBER_HOME/receipt.json" >/dev/null 2>&1; then
  ok "receipt verifies offline (exit 0)"
else
  die "receipt failed to verify"
fi
"$PY" -c "import json,sys; p=sys.argv[1]; d=json.load(open(p)); d['action']['human_summary']='TAMPERED'; json.dump(d,open(p,'w'))" "$COMMUNITY_MEMBER_HOME/receipt.json"
if "$CM" receipt verify "$COMMUNITY_MEMBER_HOME/receipt.json" >/dev/null 2>&1; then
  die "tampered receipt was ACCEPTED (should have failed)"
else
  ok "tampered receipt rejected (non-zero exit)"
fi

hr "DONE — the SMB loop works end to end, offline-verifiable, no production writes"
printf '   express onboard → book → verify offline (tamper rejected). No index involved.\n\n'
