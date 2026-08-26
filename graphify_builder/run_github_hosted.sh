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

# Product authority is the real clean detached Git checkout. The JSON source proof
# is additional provenance only. Trusted Git uses fixed argv/shell=False and no hooks.
python - "$PRODUCT_ROOT" "$PRODUCT_SHA" "$SOURCE_PROOF" <<'PY'
import pathlib, sys
from graphify_builder.runtime import (
    assert_runtime, assert_sensitive_environment_absent,
    validate_source_proof, verify_git_checkout,
)
from graphify_builder.policy import PRODUCT_REPOSITORY
assert_runtime()
assert_sensitive_environment_absent()
root = pathlib.Path(sys.argv[1])
sha = sys.argv[2]
verify_git_checkout(root, sha, PRODUCT_REPOSITORY)
validate_source_proof(pathlib.Path(sys.argv[3]), sha, PRODUCT_REPOSITORY)
print(f"verified_product_git_head={sha} repository={PRODUCT_REPOSITORY}")
PY

# Freeze the independently verified checkout before any networked dependency phase.
if find "$PRODUCT_ROOT" -type l -print -quit | grep -q .; then
  echo "product symlink forbidden" >&2
  exit 1
fi
chmod -R a-w "$PRODUCT_ROOT"
python - "$PRODUCT_ROOT" "$PRODUCT_SHA" <<'PY'
import pathlib, sys
from graphify_builder.policy import PRODUCT_REPOSITORY
from graphify_builder.runtime import assert_product_read_only, verify_git_checkout
root = pathlib.Path(sys.argv[1]); sha = sys.argv[2]
assert_product_read_only(root)
verify_git_checkout(root, sha, PRODUCT_REPOSITORY)
PY

# Phase A: only immutable lock-selected wheels may be fetched; the Python
# implementation enforces allowed package hosts, exact filenames and hashes.
python -m graphify_builder.wheelhouse \
  --uv-lock "$UPSTREAM_ROOT/uv.lock" \
  --license-root "$UPSTREAM_ROOT" \
  --wheelhouse "$WHEELHOUSE"

PYTHON="$(python -c 'import sys; print(sys.executable)')"
python - <<'PY'
from graphify_builder.runtime import assert_runtime
assert_runtime()
PY
UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
mkdir -p "$OUTPUT"

# Phase B: network is denied before the builder parses product content. Root is
# used only to create namespaces; setpriv immediately drops back to the runner
# uid/gid before any product parsing. The Python parent establishes the exact
# v2 boundary and starts the 900-second monotonic clock only after re-verifying
# the frozen Git checkout, wheelhouse, network denial, provider deny, and read-only source.
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
