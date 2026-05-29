#!/usr/bin/env bash
# Interactively create $XDG_CONFIG_HOME/pdtui/session.json from a bearer token
# captured out-of-band (browser devtools, mitmproxy, or a logged-in JS-SDK CLI).
#
# The session file is **never** committed (.gitignore excludes it). Tokens are
# read into a variable then written via printf with restrictive perms.

set -euo pipefail

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/pdtui"
CONFIG_FILE="$CONFIG_DIR/session.json"

if [[ -f "$CONFIG_FILE" ]]; then
    cat <<MSG
==> $CONFIG_FILE already exists.
    Move or delete it if you want to replace it. Aborting to avoid clobber.
MSG
    exit 1
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

cat <<MSG
==> Capture a bearer token + UID from a logged-in Proton session.

   Option A — Web (Firefox / Chrome devtools):
     1. Open https://drive.proton.me, log in, open any folder
     2. Devtools → Network → pick any /api/drive/v2/... request
     3. Request Headers → copy:
          Authorization: Bearer <PASTE THIS AS ACCESS TOKEN>
          x-pm-uid:      <PASTE THIS AS UID>

   Option B — JS SDK CLI (if you have it built locally):
     The CLI persists a session in auth-session.json. Read it:
       jq -r '.AccessToken' auth-session.json   # → AccessToken
       jq -r '.UID'         auth-session.json   # → UID

MSG

read -r -p "AccessToken: " ACCESS_TOKEN
[[ -n "$ACCESS_TOKEN" ]] || { echo "empty token, aborting"; exit 2; }
read -r -p "UID:         " UID_VAL
[[ -n "$UID_VAL" ]] || { echo "empty uid, aborting"; exit 2; }

# Note: tokens are written via process substitution, not echoed to history.
TMP=$(mktemp)
chmod 600 "$TMP"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<JSON
{
  "AccessToken": "$ACCESS_TOKEN",
  "UID": "$UID_VAL"
}
JSON

mv "$TMP" "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
trap - EXIT

echo
echo "✓ wrote $CONFIG_FILE (mode 0600)"
echo
echo "Verify with: scripts/run-probes.sh"
