#!/usr/bin/env bash
# Run the live probes via both backends (Rust + Node), then diff their outputs.
# Requires:
#   - scripts/configure-session.sh has been run
#   - rust/target/release/pdtui exists (run scripts/setup.sh first)
#   - node 20+ in PATH for the Tier-A JS backend

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

BIN="$ROOT/rust/target/release/pdtui"
if [[ ! -x "$BIN" ]]; then
    echo "==> pdtui binary missing. Run scripts/setup.sh first." >&2
    exit 1
fi

OUT_DIR="${TMPDIR:-/tmp}/pdtui-probe-$$"
mkdir -p "$OUT_DIR"
trap 'rm -rf "$OUT_DIR"' EXIT

echo "==> Rust backend (M1 DTOs + M3 HTTP middleware)"
if "$BIN" probe > "$OUT_DIR/rust.jsonl" 2>"$OUT_DIR/rust.err"; then
    RUST_OK=1
else
    RUST_OK=0
    echo "    rust probe exited non-zero (see $OUT_DIR/rust.err)"
fi
echo "    output: $OUT_DIR/rust.jsonl ($(wc -l < "$OUT_DIR/rust.jsonl") lines)"

if command -v node >/dev/null 2>&1; then
    echo
    echo "==> Node backend (Tier-A, raw fetch)"
    if node "$ROOT/scripts/js-probe.mjs" > "$OUT_DIR/js.jsonl" 2>"$OUT_DIR/js.err"; then
        JS_OK=1
    else
        JS_OK=0
        echo "    node probe exited non-zero (see $OUT_DIR/js.err)"
    fi
    echo "    output: $OUT_DIR/js.jsonl"
else
    echo "==> skipping Node backend (node not installed)"
    JS_OK=skip
fi

echo
echo "==> Per-probe status (rust | js)"
if command -v jq >/dev/null 2>&1; then
    paste \
        <(jq -r '"\(.name)\t\(.status)\t\(.ok)"' "$OUT_DIR/rust.jsonl" 2>/dev/null || echo "rust: parse error") \
        <([[ -f "$OUT_DIR/js.jsonl" ]] && jq -r '"\(.status)\t\(.ok)"' "$OUT_DIR/js.jsonl" 2>/dev/null || echo "") \
        | column -t -s $'\t'
else
    echo "    (install jq for a side-by-side table)"
    echo "    --- rust ---"; cat "$OUT_DIR/rust.jsonl"
    [[ -f "$OUT_DIR/js.jsonl" ]] && { echo "    --- js ---"; cat "$OUT_DIR/js.jsonl"; }
fi

echo
echo "==> kept under $OUT_DIR for inspection (deleted on exit)."
echo "    To preserve: cp -r $OUT_DIR ./fixtures-$(date +%Y%m%d-%H%M%S)"

if [[ "$RUST_OK" == "1" && "$JS_OK" != "0" ]]; then
    exit 0
else
    exit 1
fi
