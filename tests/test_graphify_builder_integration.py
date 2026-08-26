from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

import jsonschema

from graphify_builder import policy, runtime, wheelhouse

ROOT = Path(__file__).parents[1].resolve()
GIT = "/usr/bin/git"
FIXTURE_REPOSITORY = "hwm-tests/graphify-fixture"
TRIPWIRE = Path("/tmp/hwm-i10-0073-product-executed")
UPSTREAM_RAW = "https://raw.githubusercontent.com/Graphify-Labs/graphify/" + policy.UPSTREAM_COMMIT + "/"
CONTROL_RAW = "https://raw.githubusercontent.com/Dsamofalov/hwm-control/bc8a05f6c728d15e32048e5737d9703cd768b731/schemas/"
SCHEMAS = {
    "snapshot": ("graph-snapshot.v1.schema.json", policy.SNAPSHOT_SCHEMA_BLOB_SHA),
    "metadata": ("graph-metadata.v1.schema.json", policy.METADATA_SCHEMA_BLOB_SHA),
    "health": ("graph-health.v1.schema.json", policy.HEALTH_SCHEMA_BLOB_SHA),
}


def _run_git(root: Path, *args: str, env: dict[str, str] | None = None) -> str:
    actual_env = os.environ.copy()
    actual_env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C",
    })
    if env:
        actual_env.update(env)
    result = subprocess.run(
        [GIT, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=root, env=actual_env, shell=False, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"fixture Git command failed: {args!r}: {result.stderr[-500:]}")
    return result.stdout.strip()


def _fixture_files(root: Path) -> None:
    (root / "pkg").mkdir(parents=True, exist_ok=True)
    (root / "pkg" / "alpha.py").write_text(
        "class Alpha:\n    def value(self):\n        return 7\n\ndef beta(x):\n    return x + 1\n",
        encoding="utf-8",
    )
    (root / "pkg" / "use.py").write_text(
        "from pkg.alpha import Alpha, beta\n\ndef compute():\n    a = Alpha()\n    return beta(a.value())\n",
        encoding="utf-8",
    )
    tripwire = "from pathlib import Path\nPath('/tmp/hwm-i10-0073-product-executed').write_text('executed')\n"
    (root / "sitecustomize.py").write_text(tripwire, encoding="utf-8")
    (root / "setup.py").write_text(tripwire, encoding="utf-8")


def _make_fixture_repo(root: Path, repository: str = FIXTURE_REPOSITORY, *, detach: bool = True) -> str:
    root.mkdir(parents=True)
    _run_git(root.parent, "init", "-q", "--initial-branch=main", str(root))
    _run_git(root, "config", "user.name", "HWM Fixture")
    _run_git(root, "config", "user.email", "hwm-fixture@example.invalid")
    _run_git(root, "remote", "add", "origin", f"https://github.com/{repository}.git")
    _fixture_files(root)
    _run_git(root, "add", "--all")
    fixed = {"GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"}
    _run_git(root, "commit", "-q", "-m", "deterministic graphify fixture", env=fixed)
    sha = _run_git(root, "rev-parse", "HEAD")
    if detach:
        _run_git(root, "checkout", "-q", "--detach", sha)
    return sha


def _second_commit(root: Path) -> str:
    _run_git(root, "switch", "-q", "main")
    (root / "pkg" / "alpha.py").write_text("def changed():\n    return 9\n", encoding="utf-8")
    _run_git(root, "add", "pkg/alpha.py")
    fixed = {"GIT_AUTHOR_DATE": "2000-01-02T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-02T00:00:00Z"}
    _run_git(root, "commit", "-q", "-m", "second fixture commit", env=fixed)
    sha = _run_git(root, "rev-parse", "HEAD")
    _run_git(root, "checkout", "-q", "--detach", sha)
    return sha


def _make_read_only(root: Path) -> None:
    for path in sorted([*root.rglob("*"), root], key=lambda p: len(p.parts), reverse=True):
        try:
            path.chmod(path.stat().st_mode & ~0o222)
        except FileNotFoundError:
            pass


def _make_writable(root: Path) -> None:
    if not root.exists():
        return
    for path in [root, *root.rglob("*")]:
        try:
            if path.is_dir():
                path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IXUSR)
            else:
                path.chmod(path.stat().st_mode | stat.S_IWUSR)
        except FileNotFoundError:
            pass


def _fetch_exact(url: str, expected_git_blob: str | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "hwm-i10-0073-integration/1"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
    if expected_git_blob is not None:
        actual = wheelhouse.git_blob_sha(data)
        if actual != expected_git_blob:
            raise AssertionError(f"exact authority blob mismatch: {actual} != {expected_git_blob}")
    return data


def _exact_python() -> Path:
    candidates = []
    if platform.python_implementation() == "CPython" and platform.python_version() == policy.RUNTIME_VERSION:
        candidates.append(Path(sys.executable))
    candidates.extend([
        Path(f"/opt/hostedtoolcache/Python/{policy.RUNTIME_VERSION}/x64/bin/python"),
        Path(f"/opt/hostedtoolcache/Python/{policy.RUNTIME_VERSION}/x64/bin/python3"),
    ])
    for candidate in candidates:
        if not candidate.is_file():
            continue
        result = subprocess.run(
            [str(candidate), "-c", "import platform;print(platform.python_implementation(),platform.python_version())"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == f"CPython {policy.RUNTIME_VERSION}":
            return candidate.resolve()
    raise AssertionError(f"exact CPython {policy.RUNTIME_VERSION} is unavailable on GitHub-hosted runner")


class ExactCheckoutBindingTests(unittest.TestCase):
    def test_real_git_checkout_binding_negative_and_positive_cases(self):
        with tempfile.TemporaryDirectory(prefix="hwm-git-binding-") as tmp:
            base = Path(tmp)
            clean = base / "clean"
            clean_sha = _make_fixture_repo(clean)
            proof = base / "proof.json"
            proof.write_text(json.dumps({"repository": FIXTURE_REPOSITORY, "product_sha": clean_sha}), encoding="utf-8")
            self.assertEqual(runtime.verify_git_checkout(clean, clean_sha, FIXTURE_REPOSITORY), {"repository": FIXTURE_REPOSITORY, "product_sha": clean_sha})
            runtime.validate_source_proof(proof, clean_sha, FIXTURE_REPOSITORY)

            wrong_head = base / "wrong-head"
            first_sha = _make_fixture_repo(wrong_head)
            _second_commit(wrong_head)
            wrong_head_proof = base / "wrong-head-proof.json"
            wrong_head_proof.write_text(json.dumps({"repository": FIXTURE_REPOSITORY, "product_sha": first_sha}), encoding="utf-8")
            runtime.validate_source_proof(wrong_head_proof, first_sha, FIXTURE_REPOSITORY)
            with self.assertRaisesRegex(runtime.BoundaryError, "actual Git HEAD"):
                runtime.verify_git_checkout(wrong_head, first_sha, FIXTURE_REPOSITORY)

            bad_proof = base / "bad-proof.json"
            bad_proof.write_text(json.dumps({"repository": FIXTURE_REPOSITORY, "product_sha": "0" * 40}), encoding="utf-8")
            runtime.verify_git_checkout(clean, clean_sha, FIXTURE_REPOSITORY)
            with self.assertRaises(runtime.BoundaryError):
                runtime.validate_source_proof(bad_proof, clean_sha, FIXTURE_REPOSITORY)

            dirty = base / "dirty"; dirty_sha = _make_fixture_repo(dirty)
            (dirty / "pkg" / "alpha.py").write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(runtime.BoundaryError, "dirty tracked"):
                runtime.verify_git_checkout(dirty, dirty_sha, FIXTURE_REPOSITORY)

            untracked = base / "untracked"; untracked_sha = _make_fixture_repo(untracked)
            (untracked / "injected.py").write_text("raise SystemExit('injected')\n", encoding="utf-8")
            with self.assertRaisesRegex(runtime.BoundaryError, "untracked product"):
                runtime.verify_git_checkout(untracked, untracked_sha, FIXTURE_REPOSITORY)

            wrong_repo = base / "wrong-repo"; wrong_repo_sha = _make_fixture_repo(wrong_repo, "hwm-tests/not-the-fixture")
            with self.assertRaisesRegex(runtime.BoundaryError, "repository identity mismatch"):
                runtime.verify_git_checkout(wrong_repo, wrong_repo_sha, FIXTURE_REPOSITORY)

            missing = base / "missing-git"; missing.mkdir(); (missing / "x.py").write_text("x=1\n", encoding="utf-8")
            with self.assertRaises(runtime.BoundaryError):
                runtime.verify_git_checkout(missing, clean_sha, FIXTURE_REPOSITORY)

            attached = base / "attached"; attached_sha = _make_fixture_repo(attached, detach=False)
            with self.assertRaisesRegex(runtime.BoundaryError, "detached"):
                runtime.verify_git_checkout(attached, attached_sha, FIXTURE_REPOSITORY)

    def test_trusted_git_has_fixed_argv_no_shell_and_no_product_execution_hooks(self):
        source = (ROOT / "graphify_builder" / "runtime.py").read_text(encoding="utf-8")
        self.assertEqual(runtime.TRUSTED_GIT, Path("/usr/bin/git"))
        self.assertIn('"core.hooksPath=/dev/null"', source)
        self.assertIn("shell=False", source)
        self.assertNotIn("git submodule update", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)


class RealGraphifyIntegrationTests(unittest.TestCase):
    def test_exact_graphify_three_clean_isolated_runs_are_identical_and_contract_valid(self):
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"), "true", "real integration must run in GitHub Actions")
        self.assertEqual(os.environ.get("RUNNER_OS"), "Linux")
        self.assertEqual(os.environ.get("RUNNER_ARCH"), "X64")
        exposed = [name for name in policy.PROVIDER_ENVIRONMENT_DENY if os.environ.get(name)]
        self.assertEqual(exposed, [], f"provider environment must be absent: {exposed}")
        exact_python = _exact_python()
        self.assertEqual(policy.EXACT_GRAPHIFY_COMMAND, ("python", "-m", "graphify", "extract", ".", "--code-only", "--no-cluster", "--no-viz"))
        self.assertEqual(policy.MAX_SNAPSHOT_BYTES, 67108864)
        self.assertEqual(policy.BUILDER_TIMEOUT_SECONDS, 900)
        self.assertEqual(policy.SUPPLY_CHAIN_BLOB_SHA, "f42132a2f52d1d7af84155a56a86fca2fe4d8605")

        TRIPWIRE.unlink(missing_ok=True)
        base = Path(tempfile.mkdtemp(prefix="hwm-real-graphify-"))
        try:
            authority = base / "authority"; authority.mkdir()
            uv_bytes = _fetch_exact(UPSTREAM_RAW + "uv.lock", policy.UPSTREAM_UV_LOCK_BLOB_SHA)
            (authority / "uv.lock").write_bytes(uv_bytes)
            for name in ("LICENSE", "LICENSE-MIT", "NOTICE"):
                (authority / name).write_bytes(_fetch_exact(UPSTREAM_RAW + name))
            schemas: dict[str, dict] = {}
            for key, (name, blob_sha) in SCHEMAS.items():
                schemas[key] = json.loads(_fetch_exact(CONTROL_RAW + name, blob_sha))
            print(f"integration_authority uv_lock_blob={policy.UPSTREAM_UV_LOCK_BLOB_SHA} schema_blobs={policy.SNAPSHOT_SCHEMA_BLOB_SHA},{policy.METADATA_SCHEMA_BLOB_SHA},{policy.HEALTH_SCHEMA_BLOB_SHA}")

            wh = base / "wheelhouse"
            manifest = wheelhouse.prepare_wheelhouse(authority / "uv.lock", wh, authority)
            wheelhouse.verify_wheelhouse(wh)
            graphify = [item for item in manifest["artifacts"] if item["name"] == policy.GRAPHIFY_PACKAGE]
            self.assertEqual(len(graphify), 1)
            self.assertEqual(graphify[0]["filename"], policy.GRAPHIFY_WHEEL)
            self.assertEqual(graphify[0]["sha256"], policy.GRAPHIFY_WHEEL_SHA256)
            self.assertEqual(wheelhouse.sha256_file(wh / policy.GRAPHIFY_WHEEL), policy.GRAPHIFY_WHEEL_SHA256)
            forbidden_packages = {"openai", "anthropic", "mcp", "neo4j", "falkordb", "boto3", "psycopg"}
            self.assertFalse(forbidden_packages & {item["name"] for item in manifest["artifacts"]})
            self.assertEqual(manifest["optional_extras"], [])
            self.assertIs(manifest["build_time_resolution"], False)
            print(f"integration_wheel={policy.GRAPHIFY_WHEEL} sha256={policy.GRAPHIFY_WHEEL_SHA256}")
            print("integration_provider_environment=absent optional_provider_packages=absent")

            snapshots: list[bytes] = []; digests: list[str] = []; fixture_shas: list[str] = []
            for run_number in range(1, 4):
                fixture = base / f"fixture-{run_number}"
                fixture_sha = _make_fixture_repo(fixture); fixture_shas.append(fixture_sha)
                proof = base / f"fixture-{run_number}.source-proof.json"
                proof.write_text(json.dumps({"repository": FIXTURE_REPOSITORY, "product_sha": fixture_sha}), encoding="utf-8")
                runtime.verify_git_checkout(fixture, fixture_sha, FIXTURE_REPOSITORY)
                runtime.validate_source_proof(proof, fixture_sha, FIXTURE_REPOSITORY)
                _make_read_only(fixture)
                runtime.assert_product_read_only(fixture)
                runtime.verify_git_checkout(fixture, fixture_sha, FIXTURE_REPOSITORY)

                output = base / f"output-{run_number}"; output.mkdir()
                uid, gid = os.getuid(), os.getgid()
                cmd = [
                    "/usr/bin/sudo", "/usr/bin/unshare", "--net", "--mount", "--pid", "--fork", "--mount-proc",
                    "/usr/bin/setpriv", f"--reuid={uid}", f"--regid={gid}", "--init-groups", "/usr/bin/env", "-i",
                    "PATH=/usr/bin:/bin", f"PYTHONPATH={ROOT}", "PYTHONSAFEPATH=1", "PYTHONNOUSERSITE=1",
                    "PYTHONDONTWRITEBYTECODE=1", "GITHUB_ACTIONS=true", "RUNNER_OS=Linux", "RUNNER_ARCH=X64",
                    f"RUNNER_TEMP={os.environ['RUNNER_TEMP']}", f"GITHUB_RUN_ID={os.environ.get('GITHUB_RUN_ID', '')}",
                    str(exact_python), "-m", "graphify_builder.worker", "--product-root", str(fixture),
                    "--product-sha", fixture_sha, "--wheelhouse", str(wh), "--output", str(output),
                ]
                print(f"integration_run={run_number} network=denied command={' '.join(policy.EXACT_GRAPHIFY_COMMAND)}")
                result = subprocess.run(
                    cmd, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=policy.BUILDER_TIMEOUT_SECONDS, check=False,
                )
                if result.stdout:
                    print(result.stdout, end="")
                if result.returncode != 0:
                    self.fail(f"real Graphify run {run_number} failed rc={result.returncode}; stderr={result.stderr[-4000:]}")
                self.assertIn("hwm_graphify_command=" + " ".join(policy.EXACT_GRAPHIFY_COMMAND), result.stdout)
                self.assertIn(f"hwm_graphify_wheel={policy.GRAPHIFY_WHEEL} sha256={policy.GRAPHIFY_WHEEL_SHA256}", result.stdout)
                self.assertFalse(TRIPWIRE.exists(), "fixture product code was executed")

                snapshot_bytes = (output / "snapshot.json").read_bytes()
                metadata = json.loads((output / "metadata.json").read_text(encoding="utf-8"))
                health = json.loads((output / "health.json").read_text(encoding="utf-8"))
                snapshot = json.loads(snapshot_bytes)
                self.assertLessEqual(len(snapshot_bytes), policy.MAX_SNAPSHOT_BYTES)
                jsonschema.Draft202012Validator(schemas["snapshot"]).validate(snapshot)
                jsonschema.Draft202012Validator(schemas["metadata"], format_checker=jsonschema.FormatChecker()).validate(metadata)
                jsonschema.Draft202012Validator(schemas["health"]).validate(health)
                self.assertEqual(health["state"], "healthy_current")
                self.assertTrue(health["usable"])
                digest = hashlib.sha256(snapshot_bytes).hexdigest()
                self.assertEqual(metadata["snapshot_sha256"], digest)
                snapshots.append(snapshot_bytes); digests.append(digest)
                print(f"integration_run={run_number} canonical_sha256={digest} bytes={len(snapshot_bytes)}")
                _make_writable(fixture)

            self.assertEqual(len(set(fixture_shas)), 1, "fixture Git identity must be deterministic")
            self.assertEqual(snapshots[0], snapshots[1]); self.assertEqual(snapshots[1], snapshots[2])
            self.assertEqual(len(set(digests)), 1)
            self.assertFalse(TRIPWIRE.exists())
            print(f"integration_three_run_digest={digests[0]} runs=3 identical=true")
            print("integration_production_graph_publication=none temporary_outputs_only=true")
        finally:
            TRIPWIRE.unlink(missing_ok=True)
            if base.exists():
                for fixture in base.glob("fixture-*"):
                    _make_writable(fixture)
                shutil.rmtree(base, ignore_errors=False)
        self.assertFalse(base.exists(), "temporary real Graphify outputs were not deleted")


if __name__ == "__main__":
    unittest.main()
