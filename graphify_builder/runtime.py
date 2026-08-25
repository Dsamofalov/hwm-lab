from __future__ import annotations

import json
import os
import platform
import re
import stat
from pathlib import Path

from .policy import (
    ADDITIONAL_CREDENTIAL_ENV_DENY,
    PROVIDER_ENVIRONMENT_DENY,
    RUNTIME_VERSION,
)
from .wheelhouse import verify_wheelhouse


class BoundaryError(RuntimeError):
    pass


def validate_source_proof(path: Path, requested_sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", requested_sha):
        raise BoundaryError("requested product SHA must be exact 40-hex")
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BoundaryError("source proof missing/malformed") from exc
    if proof != {"repository": "Dsamofalov/hwm_predictor", "product_sha": requested_sha}:
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
    # These checks establish the exact v2 start boundary and intentionally occur before the timer starts.
    validate_source_proof(source_proof, product_sha)
    assert_github_hosted_disposable()
    manifest = verify_wheelhouse(wheelhouse)
    assert_sensitive_environment_absent()
    assert_network_denied()
    assert_product_read_only(product_root)
    return manifest
