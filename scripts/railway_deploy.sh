#!/usr/bin/env bash
#
# Deploy the Orrery server to Railway with an ACCURATE /health provenance stamp
#.
#
# WHY: the mesh deploys with `railway up`, which uploads the LOCAL working tree
# WITHOUT `.git` (excluded) and does NOT populate Railway's
# `RAILWAY_GIT_COMMIT_SHA` (that is only set for github-connected deploys). So a
# build-time `git rev-parse` sees nothing and `/health git_commit` falls back to
# a stale value. This script injects the real deployed commit as a deploy-time
# env var (`APP_GIT_COMMIT`), which the server reads at the TOP of its build-info
# resolution — so `/health` reports the commit that was actually shipped.
#
# USAGE:
#   scripts/railway_deploy.sh <projectId> <service> [environment]
# EXAMPLE:
#   scripts/railway_deploy.sh <projectId> <service> production
#
# The concrete project id + service names for the live demo mesh are operator
# control-plane detail — keep them in the gitignored infra/railway-deploy.md,
# not in this tracked script.
#
# Run from a clean checkout at the commit you intend to deploy.
set -euo pipefail

PROJECT="${1:?usage: railway_deploy.sh <projectId> <service> [environment]}"
SERVICE="${2:?service name, e.g. <service>}"
ENVIRONMENT="${3:-production}"

COMMIT="$(git rev-parse HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "→ stamping deploy provenance: APP_GIT_COMMIT=$COMMIT (branch=$BRANCH)"
# Set the stamp BEFORE the upload so the shipped process reads the real HEAD.
# --skip-deploys avoids an intermediate redeploy of the OLD code on the var
# change; `railway up` below is the single real deploy that ships this commit.
railway variables \
  --set "APP_GIT_COMMIT=$COMMIT" \
  --set "APP_GIT_BRANCH=$BRANCH" \
  --set "APP_BUILD_TIMESTAMP=$TS" \
  --skip-deploys \
  -s "$SERVICE" -p "$PROJECT" -e "$ENVIRONMENT"

echo "→ railway up ($SERVICE @ $PROJECT/$ENVIRONMENT)"
railway up -s "$SERVICE" -p "$PROJECT" -e "$ENVIRONMENT" --ci

echo "✓ deployed $COMMIT — verify: curl -s <public-url>/health | jq -r .git_commit  (must == $COMMIT)"
