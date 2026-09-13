#!/usr/bin/env bash
# deploy-github.sh — push this repo to GitHub (the only step needing credentials)
# Prereq (pick one):
#   gh auth login                      # or:
#   git config credential.helper store # then paste a PAT on first push
#   export GH_TOKEN=ghp_xxx            # gh CLI picks this up automatically
set -euo pipefail
cd "$(dirname "$0")"

REMOTE="https://github.com/witternif2003-beep/wh-anomaly-engine.git"  # existing, empty, confirmed via ls-remote

if [ ! -d .git ]; then
  git init -b main
  git add .
  git commit -m "WH Anomaly Tracker — boot-verified pipeline (Node 22, redis v4 msg.message fix)"
fi

git remote remove origin 2>/dev/null || true
git remote add origin "$REMOTE"

if [ -n "${GH_TOKEN:-}" ] && command -v gh >/dev/null 2>&1; then
  gh auth setup-git
fi

git push -u origin main
echo "✅ Deployed → ${REMOTE%.git}"
