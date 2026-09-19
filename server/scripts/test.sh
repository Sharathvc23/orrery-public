#!/usr/bin/env bash
# Test your agent's A2A endpoint and NEST registration.
# Usage: bash scripts/test.sh [port]

set -euo pipefail

PORT="${1:-7000}"
BASE="http://localhost:${PORT}"

echo "=== Health Check ==="
curl -s "${BASE}/health" | python3 -m json.tool
echo ""

echo "=== A2A: Basic Message ==="
curl -s -X POST "${BASE}/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "user",
    "content": {"type": "text", "text": "Hello, are you online?"},
    "conversation_id": "test-001"
  }' | python3 -m json.tool
echo ""

echo "=== A2A: Question ==="
curl -s -X POST "${BASE}/a2a" \
  -H "Content-Type: application/json" \
  -d '{
    "role": "user",
    "content": {"type": "text", "text": "What can you help me with?"},
    "conversation_id": "test-002"
  }' | python3 -m json.tool
echo ""

echo "=== AgentFacts ==="
curl -s "${BASE}/agentfacts.json" | python3 -m json.tool
echo ""

echo "All tests passed."
