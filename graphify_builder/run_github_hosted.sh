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
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "$PRODUCT_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "product SHA must be exact lowercase 40-hex" >&2; exit 2; }
[[ -d "$PRODUCT_ROOT" && -f "$SOURCE_PROOF" && -f "$UPSTREAM_ROOT/uv.lock" ]] || exit 2

# Product authority is the real clean detached Git checkout. The JSON source proof
# is additional provenance only. Trusted Git uses fixed argv/shell=False and no hooks.
python - "$PRODUCT_ROOT" "$PRODUCT_SHA" "$SOURCE_PROOF" <<'PY'
import pathlib, sys
from graphify_builder.runtime import (
    assert_sensitive_environment_absent,
    validate_source_proof,
    verify_git_checkout,
)
from graphify_builder.policy import PRODUCT_REPOSITORY
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

mkdir -p "$OUTPUT"

# Phase B: runtime-v2 acquisition and verified setup are completed before the
# semantic builder timer. ExactRuntimeSession supplies the pinned CPython 3.12.10
# and its executor supplies the containment boundary (`unshare --net`,
# `setpriv --reuid`) before product parsing. No host/toolcache Python is accepted.
python - "$ROOT" "$PRODUCT_ROOT" "$PRODUCT_SHA" "$SOURCE_PROOF" "$WHEELHOUSE" "$OUTPUT" <<'PY'
import os
from pathlib import Path
import subprocess
import sys

from graphify_acceptance_runtime import ExactRuntimeSession
from graphify_builder.policy import BUILDER_TIMEOUT_SECONDS

root = Path(sys.argv[1]).resolve()
product_root = Path(sys.argv[2]).resolve()
product_sha = sys.argv[3]
source_proof = Path(sys.argv[4]).resolve()
wheelhouse = Path(sys.argv[5]).resolve()
output = Path(sys.argv[6]).resolve()
os.chdir(root)

session = ExactRuntimeSession(os.environ["RUNNER_TEMP"])
try:
    session.prepare()
    if session.python is None or session.provenance is None:
        raise RuntimeError("runtime-v2 session did not become ready")
    executor = session.seal_network()
    provenance = session.provenance
    print(
        "hwm_runtime_v2 "
        f"runtime={provenance.executable_report} "
        f"artifact={provenance.artifact_filename} "
        f"bytes={provenance.artifact_bytes} "
        f"sha256={provenance.artifact_sha256} "
        f"redirects={provenance.redirect_count} "
        f"final_host={provenance.final_host} "
        f"inventory_sha256={provenance.canonical_inventory_sha256}",
        flush=True,
    )
    command = [
        "/usr/bin/env",
        "PATH=/usr/bin:/bin",
        f"PYTHONPATH={root}",
        "PYTHONSAFEPATH=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONDONTWRITEBYTECODE=1",
        "GITHUB_ACTIONS=true",
        "RUNNER_OS=Linux",
        "RUNNER_ARCH=X64",
        f"RUNNER_TEMP={os.environ['RUNNER_TEMP']}",
        f"GITHUB_RUN_ID={os.environ.get('GITHUB_RUN_ID', '')}",
        str(session.python), "-m", "graphify_builder.run",
        "--product-root", str(product_root),
        "--product-sha", product_sha,
        "--source-proof", str(source_proof),
        "--wheelhouse", str(wheelhouse),
        "--output", str(output),
    ]
    try:
        result = executor.run(
            "product_parsing",
            command,
            timeout=BUILDER_TIMEOUT_SECONDS + 60,
        )
    except subprocess.CalledProcessError as exc:
        if exc.stdout:
            print(exc.stdout, end="")
        if exc.stderr:
            print(exc.stderr, end="", file=sys.stderr)
        raise SystemExit(exc.returncode or 1)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
finally:
    session.cleanup()

if session.install_root.exists() or session.scratch_root.exists():
    raise RuntimeError("runtime-v2 cleanup did not remove task-local targets")
print("hwm_runtime_v2_cleanup=true", flush=True)
PY
