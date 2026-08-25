from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .normalize import canonical_json
from .policy import BUILDER_TIMEOUT_SECONDS, TIMEOUT_HEALTH_STATE
from .runtime import preflight_boundary


@dataclass(frozen=True)
class BuildConfig:
    product_root: Path
    product_sha: str
    source_proof: Path
    wheelhouse: Path
    output: Path


def _timeout_health(product_sha: str) -> dict:
    return {
        "schema": "hwm-graph-health/v1",
        "state": TIMEOUT_HEALTH_STATE,
        "usable": False,
        "requested_product_sha": product_sha,
        "snapshot_product_sha": None,
        "reason_code": "timeout_incomplete_build",
        "detail": "exact 900-second monotonic builder deadline reached; partial output discarded",
    }


def _discard_partial(output: Path) -> None:
    if not output.exists():
        output.mkdir(parents=True)
        return
    for child in list(output.iterdir()):
        if child.name == "health.json":
            child.unlink(missing_ok=True)
        elif child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def _write_timeout_health(output: Path, product_sha: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    tmp = output / "health.json.tmp"
    tmp.write_bytes(canonical_json(_timeout_health(product_sha)))
    os.replace(tmp, output / "health.json")


def _terminate_process_tree(proc: subprocess.Popen, *, sleep: Callable[[float], None] = time.sleep,
                            killpg: Callable[[int, int], None] = os.killpg) -> None:
    try:
        killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    for _ in range(20):
        if proc.poll() is not None:
            return
        sleep(0.1)
    try:
        killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_disposable(config: BuildConfig, *, clock: Callable[[], float] = time.monotonic,
                   popen_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
                   preflight: Callable[[Path, str, Path, Path], object] = preflight_boundary,
                   sleep: Callable[[float], None] = time.sleep,
                   killpg: Callable[[int, int], None] = os.killpg) -> int:
    # A retry must be a new clean disposable execution. Never consume prior partial artifacts.
    if config.output.exists() and any(config.output.iterdir()):
        raise RuntimeError("output directory is not clean; partial output reuse is forbidden")
    config.output.mkdir(parents=True, exist_ok=True)

    # Exact v2 start boundary. No clock read occurs before all four preconditions are established.
    preflight(config.product_root, config.product_sha, config.source_proof, config.wheelhouse)
    started = clock()
    cmd = [
        sys.executable, "-m", "graphify_builder.worker",
        "--product-root", str(config.product_root),
        "--product-sha", config.product_sha,
        "--wheelhouse", str(config.wheelhouse),
        "--output", str(config.output),
    ]
    proc = popen_factory(cmd, start_new_session=True)
    try:
        elapsed = max(0.0, clock() - started)
        remaining = max(0.0, BUILDER_TIMEOUT_SECONDS - elapsed)
        proc.wait(timeout=remaining)
        finished = clock()
        # A completion observed after the semantic deadline is still a timeout.
        if finished - started >= BUILDER_TIMEOUT_SECONDS:
            raise subprocess.TimeoutExpired(cmd, BUILDER_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_tree(proc, sleep=sleep, killpg=killpg)
        _discard_partial(config.output)
        _write_timeout_health(config.output, config.product_sha)
        return 124
    if proc.returncode != 0:
        # Worker failures are fail-closed health-only results; no usable snapshot may survive.
        for name in ("snapshot.json", "metadata.json", ".canonical-emission-complete"):
            (config.output / name).unlink(missing_ok=True)
        return proc.returncode or 1
    if not (config.output / ".canonical-emission-complete").is_file():
        _discard_partial(config.output)
        return 1
    # Exact v2 end boundary was reached by the child before it emitted the marker.
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--product-root", type=Path, required=True)
    p.add_argument("--product-sha", required=True)
    p.add_argument("--source-proof", type=Path, required=True)
    p.add_argument("--wheelhouse", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    return run_disposable(BuildConfig(a.product_root, a.product_sha, a.source_proof, a.wheelhouse, a.output))


if __name__ == "__main__":
    raise SystemExit(main())
