#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "Building kakoro_guard.wasm (release, wasm32v1-none)..."
cargo build --target wasm32v1-none --release -p kakoro-guard
WASM="$ROOT/target/wasm32v1-none/release/kakoro_guard.wasm"
if [[ ! -f "$WASM" ]]; then
  echo "WASM not found at $WASM" >&2
  exit 1
fi
echo "Built $WASM"
ls -l "$WASM"
