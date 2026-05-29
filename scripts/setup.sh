#!/usr/bin/env bash
# Verify the toolchain on the Linux box and run the full QE pass.
# Read-only with respect to your Proton account.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

echo "==> proton-drive-sdk setup verification"
echo "    repo: $ROOT"

if ! command -v cargo >/dev/null 2>&1; then
    cat <<MSG
==> cargo not found. Install Rust:
       curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    Then re-run this script.
MSG
    exit 1
fi

echo "==> rust toolchain"
rustc --version
cargo --version

cd "$ROOT/rust"

echo
echo "==> cargo fmt --check"
cargo fmt --all --check

echo
echo "==> cargo clippy (workspace, all-targets, -D warnings)"
cargo clippy --workspace --all-targets -- -D warnings

echo
echo "==> cargo test --workspace"
cargo test --workspace

echo
echo "==> cargo build --release -p pdtui"
cargo build --release -p pdtui

BIN="$ROOT/rust/target/release/pdtui"
SIZE=$(stat -c '%s' "$BIN" 2>/dev/null || stat -f '%z' "$BIN")
SIZE_MB=$(awk "BEGIN { printf \"%.2f\", $SIZE / 1048576 }")

echo
echo "==> pdtui binary: $BIN ($SIZE_MB MB)"
"$BIN" help

cat <<MSG

✓ Setup complete.

Next steps:
  1. Read HANDOFF.md for the lay of the land
  2. Read docs/IMPLEMENTATION-STATUS.md for what's done vs stubbed
  3. Create your session: scripts/configure-session.sh
  4. Run live probes:    scripts/run-probes.sh

MSG
