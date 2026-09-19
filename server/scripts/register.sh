#!/usr/bin/env bash
# Register your org with the registry named in REGISTRY_URL — an explicit,
# one-shot publish. There is no default registry: an unset REGISTRY_URL is a
# refusal, not a choice made for you.
# Usage: REGISTRY_URL=https://registry.example bash scripts/register.sh

set -euo pipefail

# Load config
if [ -f .env ]; then
    set -a; source .env; set +a
fi

AGENT_ID="${AGENT_ID:?Set AGENT_ID in .env}"
AGENT_NAME="${AGENT_NAME:?Set AGENT_NAME in .env}"
AGENT_DESCRIPTION="${AGENT_DESCRIPTION:-A NANDA chapter agent}"
AGENT_CAPABILITIES="${AGENT_CAPABILITIES:-conversation}"
PUBLIC_URL="${PUBLIC_URL:?Set PUBLIC_URL in .env}"
REGISTRY_URL="${REGISTRY_URL:?Set REGISTRY_URL to the registry you want this org published to — there is no default}"

echo "Registering ${AGENT_ID} at ${REGISTRY_URL}..."

curl -s -X POST "${REGISTRY_URL}/api/agents" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"${AGENT_ID}\",
    \"name\": \"${AGENT_NAME}\",
    \"endpoint\": \"${PUBLIC_URL}\",
    \"facts_url\": \"${PUBLIC_URL}/agentfacts.json\",
    \"description\": \"${AGENT_DESCRIPTION}\",
    \"capabilities\": [$(echo "${AGENT_CAPABILITIES}" | sed 's/,/","/g' | sed 's/^/"/;s/$/"/')],
    \"agent_type\": \"skill\",
    \"status\": \"running\"
  }" | python3 -m json.tool 2>/dev/null || echo "(raw response above)"

echo ""
echo "Verify: curl ${REGISTRY_URL}/api/agents/${AGENT_ID}"
