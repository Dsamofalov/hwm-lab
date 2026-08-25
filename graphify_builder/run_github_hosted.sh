#!/usr/bin/env bash
set -euo pipefail

# Unprivileged entrypoint for the disposable GitHub-hosted builder. The protected
# repository workflow surface is intentionally not modified by I10-P1.
: "${GITHUB_ACTIONS:?GitHub Actions environment required}"
: "${RUNNER_OS:?GitHub-hosted runner OS identity required}"
: "${RUNNER_ARCH:?GitHub-hosted runner architecture identity required}"
: "${RUNNER_TEMP:?GitHub-hosted disposable temp root required}"
[[ "$GITHUB_ACTIONS" == "true" && "$RUNNER_OS" == "Linux" && "$RUNNER_ARCH" == "X64" ]] || {
  echo "builder requires GitHub-hosted Linux X64 execution" >&2
  exit 2
}
[[ $# -eq 6 ]] || {
  echo "usage: $0 PRODUCT_ROOT PRODUCT_SHA SOURCE_PROOF UPSTREAM_ROOT WHEELHOUSE OUTPUT" >&2
  exit 2
}
PRODUCT_ROOT="$1"
PRODUCT_SHA="$2"
SOURCE_PROOF="$3"
UPSTREAM_ROOT="$4"
WHEELHOUSE="$5"
OUTPUT="$6"
[[ "$PRODUCT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "product SHA must be exact lowercase 40-hex" >&2; exit 2; }
[[ -d "$PRODUCT_ROOT" && -f "$SOURCE_PROOF" && -f "$UPSTREAM_ROOT/uv.lock" ]] || exit 2

# Provider/API/model/database credentials are rejected before any networked phase.
python - "$PRODUCT_SHA" "$SOURCE_PROOF" <<'PY'
import os, pathlib, sys
from graphify_builder.runtime import assert_sensitive_environment_absent, validate_source_proof, assert_runtime
assert_runtime()
assert_sensitive_environment_absent()
validate_source_proof(pathlib.Path(sys.argv[2]), sys.argv[1])
PY

# Phase A: only immutable lock-selected wheels may be fetched; the Python
# implementation enforces allowed package hosts, exact filenames and hashes.
python -m graphify_builder.wheelhouse \
  --uv-lock "$UPSTREAM_ROOT/uv.lock" \
  --license-root "$UPSTREAM_ROOT" \
  --wheelhouse "$WHEELHOUSE"

# Source readiness is metadata-only: no product module/script/hook/test/build step
# is invoked. Read-only status is established before the network-denied phase.
if find "$PRODUCT_ROOT" -type l -print -quit | grep -q .; then
  echo "product symlink forbidden" >&2
  rm -rf "$WHEELHOUSE"
  exit 1
fi
chmod -R a-w "$PRODUCT_ROOT"
[[ ! -w "$PRODUCT_ROOT" ]] || { rm -rf "$WHEELHOUSE"; exit 1; }

PYTHON="$(python -c 'import sys; print(sys.executable)')"
UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
mkdir -p "$OUTPUT"

# Phase B: network is denied before the builder parses product content. Root is
# used only to create namespaces; setpriv immediately drops back to the runner
# uid/gid before any product parsing. The Python parent then establishes the
# exact v2 timeout boundary and starts the 900-second monotonic clock.
sudo unshare --net --mount --pid --fork --mount-proc \
  setpriv --reuid="$UID_NOW" --regid="$GID_NOW" --init-groups \
  env -i \
    PATH="/usr/bin:/bin" \
    PYTHONPATH="$(cd "$(dirname "$0")/.." && pwd)" \
    GITHUB_ACTIONS="true" \
    RUNNER_OS="Linux" \
    RUNNER_ARCH="X64" \
    RUNNER_TEMP="$RUNNER_TEMP" \
    GITHUB_RUN_ID="${GITHUB_RUN_ID:-}" \
    "$PYTHON" -m graphify_builder.run \
      --product-root "$PRODUCT_ROOT" \
      --product-sha "$PRODUCT_SHA" \
      --source-proof "$SOURCE_PROOF" \
      --wheelhouse "$WHEELHOUSE" \
      --output "$OUTPUT"
