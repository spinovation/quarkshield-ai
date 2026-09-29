#!/bin/zsh
# One-shot notarized build wrapper.
# Prompts for the Apple app-specific password interactively (never stored in
# shell history, never written to disk) and runs the full signed+notarized build
# in a SINGLE shell so the credentials survive to notarytool.
#
# Usage:  ./notarize_build.command
set -e
cd "$(dirname "$0")"

unset NOTARY_PROFILE
export NOTARY_APPLE_ID="sridhargs@yahoo.com"
export NOTARY_TEAM_ID="4ADVSK467Z"

# Interactive, silent prompt (reads from the keyboard, not from pasted lines).
read -s "NOTARY_PASSWORD?Apple app-specific password (xxxx-xxxx-xxxx-xxxx): "
export NOTARY_PASSWORD
echo ""
echo "→ password captured: ${#NOTARY_PASSWORD} chars (expect 19)"

if [ "${#NOTARY_PASSWORD}" -lt 15 ]; then
  echo "✋ That doesn't look like a full app-specific password. Aborting — re-run and paste all 19 chars."
  exit 1
fi

echo "→ NOTARY_APPLE_ID=$NOTARY_APPLE_ID  NOTARY_TEAM_ID=$NOTARY_TEAM_ID  (profile unset ✓)"
echo "Starting build…"
echo ""

./build_all_and_sign.sh

# Scrub the secret from this shell before exit.
unset NOTARY_PASSWORD NOTARY_APPLE_ID NOTARY_TEAM_ID
