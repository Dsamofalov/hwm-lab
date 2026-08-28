from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

from .policy import (
    ALLOWED_PACKAGE_HOSTS,
    GRAPHIFY_PACKAGE,
    GRAPHIFY_VERSION,
    GRAPHIFY_WHEEL,
    GRAPHIFY_WHEEL_SHA256,
    GRAPHIFY_WHEEL_URL,
    RUNTIME_PLATFORM,
    RUNTIME_VERSION,
    UPSTREAM_COMMIT,
    UPSTREAM_UV_LOCK_BLOB_SHA,
)


class WheelhouseError(RuntimeError):
    pass


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split(".") if part != "")


def marker_matches(marker: str | None) -> bool:
    """Evaluate only the marker grammar actually needed by the immutable lock.

    Unknown marker syntax fails closed instead of silently selecting an artifact.
    Optional-extra markers are never accepted for the default closure.
    """
    if not marker:
        return True
    if "extra" in marker:
        return False

    def atom(value: str) -> bool:
        value = value.strip().strip("()")
        m = re.fullmatch(r"python_full_version\s*(==|!=|>=|<=|>|<)\s*'([0-9.]+)(?:\.\*)?'", value)
        if m:
            op, rhs = m.groups()
            lhs_v, rhs_v = _version_tuple(RUNTIME_VERSION), _version_tuple(rhs)
            return {"==": lhs_v == rhs_v, "!=": lhs_v != rhs_v, ">=": lhs_v >= rhs_v,
                    "<=": lhs_v <= rhs_v, ">": lhs_v > rhs_v, "<": lhs_v < rhs_v}[op]
        m = re.fullmatch(r"python_version\s*(==|!=|>=|<=|>|<)\s*'([0-9.]+)'", value)
        if m:
            op, rhs = m.groups()
            lhs_v, rhs_v = _version_tuple(".".join(RUNTIME_VERSION.split(".")[:2])), _version_tuple(rhs)
            return {"==": lhs_v == rhs_v, "!=": lhs_v != rhs_v, ">=": lhs_v >= rhs_v,
                    "<=": lhs_v <= rhs_v, ">": lhs_v > rhs_v, "<": lhs_v < rhs_v}[op]
        m = re.fullmatch(r"sys_platform\s*(==|!=)\s*'([^']+)'", value)
        if m:
            op, rhs = m.groups()
            lhs = "linux"
            return (lhs == rhs) if op == "==" else (lhs != rhs)
        raise WheelhouseError(f"unsupported lock marker: {value!r}")

    # Lock markers used for the selected closure are simple AND/OR expressions without nested logic.
    return any(all(atom(part) for part in disj.split(" and ")) for disj in marker.split(" or "))


def _package_key(package: dict) -> tuple[str, str, str]:
    source = package.get("source") or {}
    source_key = json.dumps(source, sort_keys=True, separators=(",", ":"))
    return str(package.get("name", "")), str(package.get("version", "")), source_key


def _resolve_dependency(packages: list[dict], dep: dict) -> dict:
    name = dep.get("name")
    version = dep.get("version")
    source = dep.get("source")
    candidates = [p for p in packages if p.get("name") == name]
    if version is not None:
        candidates = [p for p in candidates if p.get("version") == version]
    if source is not None:
        candidates = [p for p in candidates if p.get("source") == source]
    # The root editable package is not a registry dependency.
    candidates = [p for p in candidates if (p.get("source") or {}).get("editable") != "."]
    if len(candidates) != 1:
        raise WheelhouseError(f"lock dependency {name!r} resolves to {len(candidates)} packages")
    return candidates[0]


def select_default_closure(lock: dict) -> list[dict]:
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise WheelhouseError("uv.lock has no package array")
    roots = [p for p in packages if p.get("name") == GRAPHIFY_PACKAGE and (p.get("source") or {}).get("editable") == "."]
    if len(roots) != 1:
        raise WheelhouseError("exactly one editable graphifyy root is required in uv.lock")
    root = roots[0]
    selected: dict[tuple[str, str, str], dict] = {}
    queue = [d for d in root.get("dependencies", []) if marker_matches(d.get("marker"))]
    while queue:
        dep = queue.pop(0)
        pkg = _resolve_dependency(packages, dep)
        key = _package_key(pkg)
        if key in selected:
            continue
        selected[key] = pkg
        for child in pkg.get("dependencies", []) or []:
            if marker_matches(child.get("marker")):
                queue.append(child)
    return sorted(selected.values(), key=lambda p: (p["name"], p.get("version", "")))


def _wheel_parts(filename: str) -> tuple[str, str, str]:
    if not filename.endswith(".whl"):
        raise WheelhouseError(f"sdist/unexpected artifact forbidden: {filename}")
    stem = filename[:-4]
    parts = stem.split("-")
    if len(parts) < 5:
        raise WheelhouseError(f"malformed wheel filename: {filename}")
    return parts[-3], parts[-2], parts[-1]


def _wheel_rank(filename: str) -> tuple[int, str]:
    py_tag, abi_tag, platform_tag = _wheel_parts(filename)
    py_tags = py_tag.split(".")
    abi_tags = abi_tag.split(".")
    platform_tags = platform_tag.split(".")
    if any("musllinux" in p for p in platform_tags):
        return (-1, filename)
    platform_ok = "any" in platform_tags or any(
        ("manylinux" in p or p.startswith("linux_")) and p.endswith("x86_64") for p in platform_tags
    )
    if not platform_ok:
        return (-1, filename)
    if "py3" in py_tags and "none" in abi_tags:
        return (20 if "any" in platform_tags else 30, filename)
    if "cp312" in py_tags and "cp312" in abi_tags:
        return (100, filename)
    if "abi3" in abi_tags:
        cps = [int(t[2:]) for t in py_tags if re.fullmatch(r"cp\d+", t)]
        if cps and min(cps) <= 312:
            return (80 + min(cps), filename)
    return (-1, filename)


def select_locked_wheel(package: dict) -> dict:
    wheels = package.get("wheels") or []
    compatible: list[tuple[int, str, dict]] = []
    for entry in wheels:
        url = entry.get("url", "")
        filename = Path(urllib.parse.urlparse(url).path).name
        rank, _ = _wheel_rank(filename)
        if rank >= 0:
            compatible.append((rank, filename, entry))
    if not compatible:
        raise WheelhouseError(f"no compatible locked wheel for {package.get('name')}=={package.get('version')}")
    # Deterministic and exact: choose highest compatibility class, then lexicographically smallest filename.
    best_rank = max(item[0] for item in compatible)
    best = sorted((item for item in compatible if item[0] == best_rank), key=lambda x: x[1])[0]
    entry = best[2]
    hash_text = entry.get("hash", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", hash_text):
        raise WheelhouseError("locked wheel lacks exact sha256")
    return {
        "name": package["name"],
        "version": package["version"],
        "filename": best[1],
        "url": entry["url"],
        "sha256": hash_text.split(":", 1)[1],
        "source": "upstream uv.lock",
    }


def closure_artifacts(lock_bytes: bytes, *, verify_blob: bool = True) -> list[dict]:
    if verify_blob and git_blob_sha(lock_bytes) != UPSTREAM_UV_LOCK_BLOB_SHA:
        raise WheelhouseError("upstream uv.lock blob mismatch")
    lock = tomllib.loads(lock_bytes.decode("utf-8"))
    if lock.get("version") != 1 or lock.get("revision") != 3:
        raise WheelhouseError("uv.lock format/revision mismatch")
    artifacts = [select_locked_wheel(package) for package in select_default_closure(lock)]
    artifacts.append({
        "name": GRAPHIFY_PACKAGE,
        "version": GRAPHIFY_VERSION,
        "filename": GRAPHIFY_WHEEL,
        "url": GRAPHIFY_WHEEL_URL,
        "sha256": GRAPHIFY_WHEEL_SHA256,
        "source": "hwm-graphify-supply-chain/v2",
    })
    names = [a["filename"] for a in artifacts]
    if len(names) != len(set(names)):
        raise WheelhouseError("duplicate wheel filename in selected closure")
    return sorted(artifacts, key=lambda a: (a["name"], a["version"], a["filename"]))


def _validate_download_url(url: str, filename: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PACKAGE_HOSTS:
        raise WheelhouseError(f"package host forbidden: {url}")
    if Path(parsed.path).name != filename:
        raise WheelhouseError("download filename does not match immutable selection")
    if not filename.endswith(".whl"):
        raise WheelhouseError("sdist/unexpected artifact forbidden")


def download_exact_artifact(artifact: dict, destination: Path) -> None:
    _validate_download_url(artifact["url"], artifact["filename"])
    target = destination / artifact["filename"]
    request = urllib.request.Request(artifact["url"], headers={"User-Agent": "hwm-i10-graphify-builder/1"})
    with urllib.request.urlopen(request, timeout=60) as response, target.open("wb") as out:
        if urllib.parse.urlparse(response.geturl()).hostname not in ALLOWED_PACKAGE_HOSTS:
            raise WheelhouseError("package download redirected outside allowlist")
        shutil.copyfileobj(response, out)
    if sha256_file(target) != artifact["sha256"]:
        target.unlink(missing_ok=True)
        raise WheelhouseError(f"sha256 mismatch for {artifact['filename']}")


def prepare_wheelhouse(uv_lock: Path, wheelhouse: Path, license_root: Path | None = None) -> dict:
    if wheelhouse.exists() and any(wheelhouse.iterdir()):
        raise WheelhouseError("wheelhouse must start empty")
    wheelhouse.mkdir(parents=True, exist_ok=True)
    lock_bytes = uv_lock.read_bytes()
    artifacts = closure_artifacts(lock_bytes, verify_blob=True)
    try:
        for artifact in artifacts:
            download_exact_artifact(artifact, wheelhouse)
        license_files: list[str] = []
        if license_root is not None:
            license_dir = wheelhouse / "licenses" / "graphifyy-0.9.38"
            license_dir.mkdir(parents=True)
            for name in ("LICENSE", "LICENSE-MIT", "NOTICE"):
                src = license_root / name
                if not src.is_file():
                    raise WheelhouseError(f"required upstream license file missing: {name}")
                shutil.copyfile(src, license_dir / name)
                license_files.append(f"licenses/graphifyy-0.9.38/{name}")
        manifest = {
            "schema": "hwm-graphify-wheelhouse/v1",
            "upstream_commit": UPSTREAM_COMMIT,
            "uv_lock_blob_sha": UPSTREAM_UV_LOCK_BLOB_SHA,
            "runtime": {"python": RUNTIME_VERSION, "platform": RUNTIME_PLATFORM},
            "artifacts": artifacts,
            "license_files": license_files,
            "optional_extras": [],
            "build_time_resolution": False,
        }
        encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        (wheelhouse / "manifest.json").write_bytes(encoded)
        (wheelhouse / ".verified-ready").write_text(hashlib.sha256(encoded).hexdigest(), encoding="ascii")
        return manifest
    except Exception:
        shutil.rmtree(wheelhouse, ignore_errors=True)
        raise


def verify_wheelhouse(wheelhouse: Path) -> dict:
    manifest_path = wheelhouse / "manifest.json"
    ready_path = wheelhouse / ".verified-ready"
    if not manifest_path.is_file() or not ready_path.is_file():
        raise WheelhouseError("verified wheelhouse marker missing")
    raw = manifest_path.read_bytes()
    if ready_path.read_text(encoding="ascii").strip() != hashlib.sha256(raw).hexdigest():
        raise WheelhouseError("wheelhouse ready marker mismatch")
    manifest = json.loads(raw)
    if manifest.get("schema") != "hwm-graphify-wheelhouse/v1":
        raise WheelhouseError("wheelhouse schema mismatch")
    if manifest.get("upstream_commit") != UPSTREAM_COMMIT or manifest.get("uv_lock_blob_sha") != UPSTREAM_UV_LOCK_BLOB_SHA:
        raise WheelhouseError("wheelhouse upstream/lock mismatch")
    if manifest.get("runtime") != {"python": RUNTIME_VERSION, "platform": RUNTIME_PLATFORM}:
        raise WheelhouseError("wheelhouse runtime mismatch")
    if manifest.get("optional_extras") != [] or manifest.get("build_time_resolution") is not False:
        raise WheelhouseError("optional/floating dependency capability forbidden")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise WheelhouseError("wheelhouse artifact list missing")
    graphify = [a for a in artifacts if a.get("name") == GRAPHIFY_PACKAGE]
    if graphify != [{
        "filename": GRAPHIFY_WHEEL,
        "name": GRAPHIFY_PACKAGE,
        "sha256": GRAPHIFY_WHEEL_SHA256,
        "source": "hwm-graphify-supply-chain/v2",
        "url": GRAPHIFY_WHEEL_URL,
        "version": GRAPHIFY_VERSION,
    }]:
        raise WheelhouseError("Graphify package/wheel pin mismatch")
    expected_files = set()
    for artifact in artifacts:
        filename = artifact.get("filename", "")
        _validate_download_url(artifact.get("url", ""), filename)
        if not re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")):
            raise WheelhouseError("artifact hash malformed")
        path = wheelhouse / filename
        if not path.is_file() or sha256_file(path) != artifact["sha256"]:
            raise WheelhouseError(f"wheelhouse artifact mismatch: {filename}")
        expected_files.add(filename)
    unexpected = {p.name for p in wheelhouse.iterdir() if p.is_file()} - expected_files - {"manifest.json", ".verified-ready"}
    if unexpected:
        raise WheelhouseError(f"unexpected artifact(s): {sorted(unexpected)}")
    return manifest


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uv-lock", required=True, type=Path)
    parser.add_argument("--wheelhouse", required=True, type=Path)
    parser.add_argument("--license-root", type=Path)
    args = parser.parse_args(argv)
    prepare_wheelhouse(args.uv_lock, args.wheelhouse, args.license_root)
    verify_wheelhouse(args.wheelhouse)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
