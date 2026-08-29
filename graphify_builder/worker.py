from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .missing_node_diagnostic import diagnose_missing_discriminator_nodes
from .normalize import (
    GraphOutputError, OversizedSnapshotError, SnapshotSchemaError, canonical_json, normalize_graph,
)
from .policy import (
    ADDITIONAL_CREDENTIAL_ENV_DENY,
    EXACT_GRAPHIFY_COMMAND,
    GRAPHIFY_PACKAGE,
    PROVIDER_ENVIRONMENT_DENY,
)
from .runtime import BoundaryError, assert_product_read_only, assert_runtime, assert_sensitive_environment_absent, assert_network_denied
from .wheelhouse import WheelhouseError, verify_wheelhouse

STAGE_ORDER = (
    "offline-installation", "exact-structural-graphify-invocation", "output-parsing", "normalization",
    "schema-validation", "digest-calculation", "canonical-artifact-emission",
)


class InvocationError(RuntimeError):
    pass


def _health(state: str, requested_sha: str, reason: str, detail: str = "", snapshot_sha: str | None = None) -> dict:
    return {
        "schema": "hwm-graph-health/v1",
        "state": state,
        "usable": state == "healthy_current",
        "requested_product_sha": requested_sha,
        "snapshot_product_sha": requested_sha if state == "healthy_current" else None,
        "reason_code": reason,
        **({"detail": detail[:4096]} if detail else {}),
    }


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _clean_artifacts(output: Path) -> None:
    for name in ("snapshot.json", "metadata.json", "health.json", ".canonical-emission-complete"):
        (output / name).unlink(missing_ok=True)
    for path in output.glob("*.tmp"):
        path.unlink(missing_ok=True)


def _safe_graphify_env(venv_bin: Path, graph_out: Path, home: Path) -> dict[str, str]:
    env = dict(os.environ)
    for name in (*PROVIDER_ENVIRONMENT_DENY, *ADDITIONAL_CREDENTIAL_ENV_DENY,
                 "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                 "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        env.pop(name, None)
    env.update({
        "PATH": f"{venv_bin}:/usr/bin:/bin",
        "PYTHONSAFEPATH": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GRAPHIFY_OUT": str(graph_out),
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
    })
    return env


def execute(product_root: Path, product_sha: str, wheelhouse: Path, output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    _clean_artifacts(output)
    start = time.monotonic()
    scratch = Path(tempfile.mkdtemp(prefix="hwm-graphify-worker-", dir=output))
    try:
        assert_runtime()
        assert_sensitive_environment_absent()
        assert_network_denied()
        assert_product_read_only(product_root)
        manifest = verify_wheelhouse(wheelhouse)
        artifacts = [wheelhouse / item["filename"] for item in manifest["artifacts"]]
        graphify_artifact = [item for item in manifest["artifacts"] if item.get("name") == GRAPHIFY_PACKAGE]
        if len(graphify_artifact) != 1:
            raise WheelhouseError("exact Graphify artifact identity missing")
        print(
            f"hwm_graphify_wheel={graphify_artifact[0]['filename']} "
            f"sha256={graphify_artifact[0]['sha256']}",
            flush=True,
        )

        venv = scratch / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, env=_safe_graphify_env(Path("/nonexistent"), scratch / "unused", scratch / "home"))
        venv_python = venv / "bin" / "python"
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "--disable-pip-version-check", "--no-index", "--no-deps", *map(str, artifacts)],
            check=True, env=_safe_graphify_env(venv / "bin", scratch / "unused", scratch / "home"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        graph_out = scratch / "graphify-out"
        home = scratch / "home"; home.mkdir(exist_ok=True)
        env = _safe_graphify_env(venv / "bin", graph_out, home)
        print("hwm_graphify_command=" + " ".join(EXACT_GRAPHIFY_COMMAND), flush=True)
        result = subprocess.run(
            list(EXACT_GRAPHIFY_COMMAND), cwd=product_root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        if result.returncode != 0:
            raise InvocationError(f"Graphify structural extraction failed ({result.returncode}): {result.stderr[-2000:]}")

        graph_path = graph_out / "graph.json"
        if not graph_path.is_file():
            raise GraphOutputError("Graphify graph.json missing")
        try:
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise GraphOutputError("Graphify graph.json malformed") from exc

        diagnostic = diagnose_missing_discriminator_nodes(graph)
        if diagnostic is not None:
            diagnostic_text = canonical_json(diagnostic).decode("utf-8")
            print("hwm_missing_node_semantic_diagnostic=" + diagnostic_text, flush=True)
            raise GraphOutputError("missing node semantic diagnostic: " + diagnostic_text)

        snapshot, snapshot_bytes, snapshot_sha = normalize_graph(graph, product_sha, product_root)
        metadata = {
            "schema": "hwm-graph-metadata/v1",
            "snapshot_sha256": snapshot_sha,
            "product_sha": product_sha,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "workflow_run_id": int(os.environ["GITHUB_RUN_ID"]) if os.environ.get("GITHUB_RUN_ID", "").isdigit() else None,
            "build_duration_seconds": max(0.0, time.monotonic() - start),
            "node_count": len(snapshot["nodes"]),
            "edge_count": len(snapshot["edges"]),
        }
        health = _health("healthy_current", product_sha, "exact_sha_structural_build_complete", snapshot_sha=snapshot_sha)

        staged = scratch / "emit"; staged.mkdir()
        (staged / "snapshot.json").write_bytes(snapshot_bytes)
        (staged / "metadata.json").write_bytes(canonical_json(metadata))
        (staged / "health.json").write_bytes(canonical_json(health))
        for name in ("snapshot.json", "metadata.json", "health.json"):
            os.replace(staged / name, output / name)
        _write_atomic(output / ".canonical-emission-complete", b"complete")
        print(f"hwm_canonical_snapshot_sha256={snapshot_sha}", flush=True)
        return 0
    except OversizedSnapshotError as exc:
        state, reason, detail = "oversized_artifact", "snapshot_over_67108864_bytes", str(exc)
    except (GraphOutputError, InvocationError) as exc:
        state, reason, detail = "incompatible_upstream_output", "malformed_or_incompatible_graphify_output", str(exc)
    except SnapshotSchemaError as exc:
        state, reason, detail = "malformed_snapshot", "schema_invalid_output", str(exc)
    except (WheelhouseError, BoundaryError, subprocess.SubprocessError, OSError) as exc:
        state, reason, detail = "unsupported_upstream", "supply_chain_or_runtime_policy_violation", str(exc)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    _clean_artifacts(output)
    health = _health(state, product_sha, reason, detail)
    _write_atomic(output / "health.json", canonical_json(health))
    return 1


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--product-root", type=Path, required=True)
    p.add_argument("--product-sha", required=True)
    p.add_argument("--wheelhouse", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    return execute(args.product_root, args.product_sha, args.wheelhouse, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
