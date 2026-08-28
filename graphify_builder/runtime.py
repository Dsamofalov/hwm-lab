from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
from pathlib import Path

from .policy import (
    ADDITIONAL_CREDENTIAL_ENV_DENY,
    PRODUCT_REPOSITORY,
    PROVIDER_ENVIRONMENT_DENY,
    RUNTIME_VERSION,
)
from .wheelhouse import verify_wheelhouse


class BoundaryError(RuntimeError):
    pass


TRUSTED_GIT = Path("/usr/bin/git")
_GIT_BASE = (
    str(TRUSTED_GIT),
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "submodule.recurse=false",
)


def _git_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
        "LANG": "C",
    }


def _git(root: Path, *args: str, text: bool = True) -> subprocess.CompletedProcess:
    if not TRUSTED_GIT.is_file() or not os.access(TRUSTED_GIT, os.X_OK):
        raise BoundaryError("trusted /usr/bin/git is unavailable")
    try:
        return subprocess.run(
            [*_GIT_BASE, *args],
            cwd=root,
            env=_git_env(),
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            check=False,
        )
    except OSError as exc:
        raise BoundaryError("trusted Git metadata operation failed") from exc


def _require_git(root: Path, *args: str) -> str:
    result = _git(root, *args)
    if result.returncode != 0:
        raise BoundaryError("trusted Git metadata verification failed")
    return result.stdout.strip()


def _normalize_github_repository(url: str) -> str:
    value = url.strip()
    patterns = (
        r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$",
        r"git@github\.com:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$",
        r"ssh://git@github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, value)
        if match:
            return match.group(1)
    raise BoundaryError("checkout repository origin is not normalized trusted GitHub provenance")


def _git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _tracked_index(root: Path) -> dict[str, tuple[str, str]]:
    result = _git(root, "ls-files", "--stage", "-z", text=False)
    if result.returncode != 0:
        raise BoundaryError("cannot read trusted Git index")
    tracked: dict[str, tuple[str, str]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            meta, raw_path = record.split(b"\t", 1)
            mode_b, sha_b, stage_b = meta.split(b" ", 2)
            path = raw_path.decode("utf-8", "strict")
            mode = mode_b.decode("ascii")
            sha = sha_b.decode("ascii")
            stage = stage_b.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise BoundaryError("Git index contains unsupported path metadata") from exc
        if stage != "0" or mode not in {"100644", "100755"}:
            if mode == "160000":
                raise BoundaryError("submodule/gitlink checkout content is forbidden")
            if mode == "120000":
                raise BoundaryError("product symlink is forbidden")
            raise BoundaryError("non-regular Git index entry is forbidden")
        if not re.fullmatch(r"[0-9a-f]{40}", sha) or path in tracked:
            raise BoundaryError("Git index entry is malformed or duplicated")
        tracked[path] = (mode, sha)
    if ".gitmodules" in tracked:
        raise BoundaryError("submodule configuration is forbidden")
    return tracked


def _verify_tracked_bytes_and_untracked(root: Path, tracked: dict[str, tuple[str, str]]) -> None:
    observed_files: set[str] = set()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        if current_path == root:
            dirs[:] = [name for name in dirs if name != ".git"]
            files = [name for name in files if name != ".git"]
        for name in list(dirs):
            path = current_path / name
            if path.is_symlink():
                raise BoundaryError(f"product symlink forbidden: {path.relative_to(root).as_posix()}")
        for name in files:
            path = current_path / name
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
            except OSError as exc:
                raise BoundaryError(f"cannot inspect product path: {rel}") from exc
            if not stat.S_ISREG(info.st_mode):
                raise BoundaryError(f"special product file forbidden: {rel}")
            observed_files.add(rel)
    tracked_paths = set(tracked)
    extras = observed_files - tracked_paths
    missing = tracked_paths - observed_files
    if extras:
        raise BoundaryError("untracked product content forbidden: " + ",".join(sorted(extras)[:8]))
    if missing:
        raise BoundaryError("tracked product content missing: " + ",".join(sorted(missing)[:8]))
    for rel, (expected_mode, expected_sha) in tracked.items():
        path = root / rel
        try:
            info = path.lstat()
            actual_sha = _git_blob_sha(path.read_bytes())
        except OSError as exc:
            raise BoundaryError(f"cannot read tracked product data: {rel}") from exc
        expected_executable = expected_mode == "100755"
        actual_executable = bool(info.st_mode & stat.S_IXUSR)
        if actual_executable != expected_executable:
            raise BoundaryError(f"dirty tracked product mode forbidden: {rel}")
        if actual_sha != expected_sha:
            raise BoundaryError(f"dirty tracked product content forbidden: {rel}")


def verify_git_checkout(root: Path, requested_sha: str, expected_repository: str = PRODUCT_REPOSITORY) -> dict[str, str]:
    """Bind source bytes to an exact clean detached Git commit without executing product commands."""
    if not re.fullmatch(r"[0-9a-f]{40}", requested_sha):
        raise BoundaryError("requested product SHA must be exact 40-hex")
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("product checkout missing") from exc
    if not root.is_dir():
        raise BoundaryError("product checkout missing")
    if _require_git(root, "rev-parse", "--is-inside-work-tree") != "true":
        raise BoundaryError("product_root is not a Git worktree")
    try:
        top = Path(_require_git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exc:
        raise BoundaryError("Git worktree root cannot be resolved") from exc
    if top != root:
        raise BoundaryError("product_root is not the exact Git worktree root")
    if _require_git(root, "rev-parse", "--show-object-format") != "sha1":
        raise BoundaryError("unsupported Git object format")
    head = _require_git(root, "rev-parse", "--verify", "HEAD^{commit}")
    if head != requested_sha:
        raise BoundaryError("actual Git HEAD does not equal requested product SHA")
    symbolic = _git(root, "symbolic-ref", "-q", "HEAD")
    if symbolic.returncode == 0:
        raise BoundaryError("product HEAD must be detached to prevent branch drift")
    if symbolic.returncode != 1:
        raise BoundaryError("cannot prove detached Git HEAD")
    origins = _git(root, "config", "--get-all", "remote.origin.url")
    if origins.returncode != 0:
        raise BoundaryError("checkout repository origin missing")
    origin_values = [line for line in origins.stdout.splitlines() if line.strip()]
    if len(origin_values) != 1 or _normalize_github_repository(origin_values[0]) != expected_repository:
        raise BoundaryError("checkout repository identity mismatch")
    tracked = _tracked_index(root)
    _verify_tracked_bytes_and_untracked(root, tracked)
    if _require_git(root, "rev-parse", "--verify", "HEAD^{commit}") != requested_sha:
        raise BoundaryError("Git HEAD drifted during source verification")
    return {"repository": expected_repository, "product_sha": requested_sha}


def validate_source_proof(path: Path, requested_sha: str, expected_repository: str = PRODUCT_REPOSITORY) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", requested_sha):
        raise BoundaryError("requested product SHA must be exact 40-hex")
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BoundaryError("source proof missing/malformed") from exc
    if proof != {"repository": expected_repository, "product_sha": requested_sha}:
        raise BoundaryError("source proof does not bind exact requested product SHA")


def assert_runtime() -> None:
    if platform.python_implementation() != "CPython" or platform.python_version() != RUNTIME_VERSION:
        raise BoundaryError(f"runtime must be CPython {RUNTIME_VERSION}")
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise BoundaryError("runtime platform must be linux-x86_64")


def assert_github_hosted_disposable(env: dict[str, str] | None = None) -> None:
    env = os.environ if env is None else env
    required = {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64"}
    if any(env.get(name) != value for name, value in required.items()):
        raise BoundaryError("builder requires GitHub-hosted Linux X64 execution")
    temp = env.get("RUNNER_TEMP", "")
    if not temp or not Path(temp).is_absolute():
        raise BoundaryError("GitHub-hosted disposable temp identity missing")


def assert_sensitive_environment_absent(env: dict[str, str] | None = None) -> None:
    env = os.environ if env is None else env
    exposed = [name for name in (*PROVIDER_ENVIRONMENT_DENY, *ADDITIONAL_CREDENTIAL_ENV_DENY) if env.get(name)]
    if exposed:
        raise BoundaryError("credential/provider environment exposure: " + ",".join(sorted(exposed)))


def assert_network_denied(sys_net: Path = Path("/sys/class/net"), proc_route: Path = Path("/proc/net/route")) -> None:
    try:
        interfaces = {p.name for p in sys_net.iterdir()}
    except OSError as exc:
        raise BoundaryError("cannot prove network namespace state") from exc
    if interfaces - {"lo"}:
        raise BoundaryError(f"network policy violation; non-loopback interfaces: {sorted(interfaces - {'lo'})}")
    try:
        lines = proc_route.read_text(encoding="ascii").splitlines()[1:]
    except OSError as exc:
        raise BoundaryError("cannot inspect route table") from exc
    for line in lines:
        cols = line.split()
        if len(cols) >= 2 and cols[1] == "00000000":
            raise BoundaryError("network policy violation; default route present")


def assert_product_read_only(root: Path) -> None:
    if not root.is_dir():
        raise BoundaryError("product checkout missing")
    for path in [root, *root.rglob("*")]:
        try:
            info = path.lstat()
        except OSError as exc:
            raise BoundaryError(f"cannot inspect product path: {path}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise BoundaryError(f"product symlink forbidden: {path.relative_to(root)}")
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise BoundaryError(f"special product file forbidden: {path.relative_to(root)}")
        if info.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
            raise BoundaryError(f"product checkout is not read-only: {path.relative_to(root)}")


def preflight_boundary(product_root: Path, product_sha: str, source_proof: Path, wheelhouse: Path) -> dict:
    verify_git_checkout(product_root, product_sha, PRODUCT_REPOSITORY)
    validate_source_proof(source_proof, product_sha, PRODUCT_REPOSITORY)
    assert_github_hosted_disposable()
    manifest = verify_wheelhouse(wheelhouse)
    assert_sensitive_environment_absent()
    assert_network_denied()
    assert_product_read_only(product_root)
    return manifest
