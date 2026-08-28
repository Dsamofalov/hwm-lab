from __future__ import annotations

import contextlib
import hashlib
import http.client
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import time
from typing import Callable, Sequence
from urllib.parse import urlparse

RELEASE_TAG = "3.12.10-14343898437"
ARTIFACT_FILENAME = "python-3.12.10-linux-24.04-x64.tar.gz"
ARTIFACT_URL = (
    "https://github.com/actions/python-versions/releases/download/"
    f"{RELEASE_TAG}/{ARTIFACT_FILENAME}"
)
ARTIFACT_BYTES = 121612690
ARTIFACT_SHA256 = "b9bd943c5fc9244f796deef42c59d29ab9278d8a718851c67de6b44846320f33"
FINAL_REDIRECT_HOST = "release-assets.githubusercontent.com"
EXPECTED_REPORT = "CPython 3.12.10"
INSTALL_DIRNAME = "task-local"
SCRATCH_DIRNAME = "i10-0085-runtime-acquisition"
DOWNLOAD_TIMEOUT_SECONDS = 30
SETUP_TIMEOUT_SECONDS = 180
VERSION_TIMEOUT_SECONDS = 30
PROTECTED_PHASES = frozenset({"artifact_setup", "product_parsing", "graphify_invocation"})


class RuntimeAcquisitionError(RuntimeError):
    pass


@dataclass(frozen=True)
class _RuntimeContract:
    url: str
    filename: str
    size: int
    sha256: str
    redirect_host: str
    executable_report: str


EXACT_CONTRACT = _RuntimeContract(
    url=ARTIFACT_URL,
    filename=ARTIFACT_FILENAME,
    size=ARTIFACT_BYTES,
    sha256=ARTIFACT_SHA256,
    redirect_host=FINAL_REDIRECT_HOST,
    executable_report=EXPECTED_REPORT,
)


@dataclass(frozen=True)
class RuntimeProvenance:
    artifact_url: str
    artifact_filename: str
    artifact_bytes: int
    artifact_sha256: str
    redirect_count: int
    final_host: str
    install_root: str
    executable_report: str
    runtime_ready_monotonic: float


class _Response:
    def __init__(self, raw: http.client.HTTPResponse, connection: http.client.HTTPSConnection):
        self.raw = raw
        self.connection = connection

    @property
    def status(self) -> int:
        return self.raw.status

    def getheader(self, name: str) -> str | None:
        return self.raw.getheader(name)

    def read(self, amount: int = -1) -> bytes:
        return self.raw.read(amount)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.raw.close()
        with contextlib.suppress(Exception):
            self.connection.close()


def _https_get(
    url: str,
    *,
    connection_factory: Callable[..., http.client.HTTPSConnection] = http.client.HTTPSConnection,
) -> _Response:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeAcquisitionError("runtime acquisition requires HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeAcquisitionError("runtime acquisition URL must not contain credentials")
    port = parsed.port or 443
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    connection = connection_factory(parsed.hostname, port=port, timeout=DOWNLOAD_TIMEOUT_SECONDS)
    headers = {
        "Accept": "application/octet-stream",
        "User-Agent": "hwm-i10-0085-exact-runtime/1",
    }
    # Deliberately no Authorization, Cookie, Proxy-Authorization, or provider headers.
    connection.request("GET", target, headers=headers)
    return _Response(connection.getresponse(), connection)


def _verify_initial_identity(contract: _RuntimeContract) -> None:
    parsed = urlparse(contract.url)
    if parsed.scheme != "https":
        raise RuntimeAcquisitionError("artifact URL must use HTTPS")
    if parsed.hostname != "github.com":
        raise RuntimeAcquisitionError("artifact URL host differs from protected contract")
    if PurePosixPath(parsed.path).name != contract.filename:
        raise RuntimeAcquisitionError("artifact filename differs from protected contract")


def _download_archive(
    destination: Path,
    *,
    contract: _RuntimeContract,
    get: Callable[[str], object],
) -> tuple[int, str, int, str]:
    _verify_initial_identity(contract)
    first = get(contract.url)
    try:
        status = int(first.status)
        if status not in {301, 302, 303, 307, 308}:
            raise RuntimeAcquisitionError("exact GitHub release URL did not produce the required single redirect")
        location = first.getheader("Location")
        if not location:
            raise RuntimeAcquisitionError("runtime redirect is missing Location")
        redirected = urlparse(location)
        if redirected.scheme != "https" or redirected.hostname != contract.redirect_host:
            raise RuntimeAcquisitionError("runtime redirect host differs from protected contract")
    finally:
        first.close()

    second = get(location)
    try:
        if int(second.status) in {301, 302, 303, 307, 308}:
            raise RuntimeAcquisitionError("runtime acquisition exceeded one redirect")
        if int(second.status) != 200:
            raise RuntimeAcquisitionError(f"runtime asset returned HTTP {second.status}")
        content_length = second.getheader("Content-Length")
        if content_length is None:
            raise RuntimeAcquisitionError("runtime asset omitted Content-Length")
        try:
            declared = int(content_length)
        except (TypeError, ValueError) as exc:
            raise RuntimeAcquisitionError("runtime asset Content-Length is not an integer") from exc
        if declared != contract.size:
            raise RuntimeAcquisitionError("runtime asset Content-Length differs from protected contract")

        hasher = hashlib.sha256()
        count = 0
        with destination.open("xb") as stream:
            while True:
                chunk = second.read(1024 * 1024)
                if not chunk:
                    break
                count += len(chunk)
                if count > contract.size:
                    raise RuntimeAcquisitionError("runtime asset exceeds protected byte count")
                stream.write(chunk)
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if count != contract.size:
            raise RuntimeAcquisitionError("runtime asset byte count differs from protected contract")
        if digest != contract.sha256:
            raise RuntimeAcquisitionError("runtime asset SHA-256 differs from protected contract")
        return count, digest, 1, contract.redirect_host
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            destination.unlink()
        raise
    finally:
        second.close()


def _safe_member_parts(member: tarfile.TarInfo) -> tuple[str, ...]:
    name = member.name
    if not name or "\x00" in name or "\\" in name:
        raise RuntimeAcquisitionError("archive member has an unsafe path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise RuntimeAcquisitionError("archive member escapes task-local root")
    if not path.parts and not member.isdir():
        raise RuntimeAcquisitionError("archive root entry must be a directory")
    if member.issym():
        raise RuntimeAcquisitionError("archive symlink entries are forbidden")
    if member.islnk():
        raise RuntimeAcquisitionError("archive hard-link entries are forbidden")
    if member.ischr() or member.isblk() or member.isfifo():
        raise RuntimeAcquisitionError("archive special-file entries are forbidden")
    if not (member.isdir() or member.isfile()):
        raise RuntimeAcquisitionError("archive contains an unsupported member type")
    return tuple(path.parts)


def _validated_members(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, tuple[str, ...]]]:
    validated: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []
    seen: set[tuple[str, ...]] = set()
    for member in archive.getmembers():
        parts = _safe_member_parts(member)
        if parts in seen:
            raise RuntimeAcquisitionError("archive contains duplicate member paths")
        seen.add(parts)
        validated.append((member, parts))
    if not validated:
        raise RuntimeAcquisitionError("runtime archive is empty")
    return validated


def _extract_verified_archive(archive_path: Path, install_root: Path, *, timeout: int = SETUP_TIMEOUT_SECONDS) -> None:
    if install_root.exists() or install_root.is_symlink():
        raise RuntimeAcquisitionError("task-local runtime target already exists")
    deadline = time.monotonic() + timeout
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = _validated_members(archive)
            if time.monotonic() >= deadline:
                raise RuntimeAcquisitionError("runtime archive validation exceeded setup timeout")
            install_root.mkdir(mode=0o700)
            for member, parts in members:
                if time.monotonic() >= deadline:
                    raise RuntimeAcquisitionError("runtime extraction exceeded setup timeout")
                if not parts:
                    continue
                target = install_root.joinpath(*parts)
                if member.isdir():
                    if target.exists():
                        if target.is_symlink() or not target.is_dir():
                            raise RuntimeAcquisitionError("archive directory collides with extracted file")
                    else:
                        target.mkdir(parents=True, exist_ok=False)
                    target.chmod(member.mode & 0o777)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeAcquisitionError("regular archive member has no file content")
                with source, target.open("xb") as output:
                    while True:
                        if time.monotonic() >= deadline:
                            raise RuntimeAcquisitionError("runtime extraction exceeded setup timeout")
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                target.chmod(member.mode & 0o777)
    except Exception:
        shutil.rmtree(install_root, ignore_errors=True)
        raise


def _find_exact_python(install_root: Path) -> Path:
    candidate = install_root / "bin" / "python3.12"
    if not candidate.is_file() or candidate.is_symlink():
        raise RuntimeAcquisitionError("verified archive did not provide task-local bin/python3.12 as a regular file")
    return candidate


def _report_python(executable: Path) -> str:
    try:
        completed = subprocess.run(
            [
                str(executable),
                "-c",
                "import platform; print(f'{platform.python_implementation()} {platform.python_version()}')",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=VERSION_TIMEOUT_SECONDS,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeAcquisitionError("task-local runtime version probe failed") from exc
    report = completed.stdout.strip()
    if report != EXPECTED_REPORT:
        raise RuntimeAcquisitionError(f"task-local interpreter report mismatch: {report!r}")
    return report


class NetworkDeniedExecutor:
    def __init__(self, runtime_root: Path):
        self.runtime_root = runtime_root

    def command_for(self, phase: str, argv: Sequence[str]) -> list[str]:
        if phase not in PROTECTED_PHASES:
            raise RuntimeAcquisitionError(f"unsupported protected phase: {phase}")
        if not argv:
            raise RuntimeAcquisitionError("protected phase command must not be empty")
        uid = os.getuid()
        gid = os.getgid()
        return [
            "sudo",
            "--non-interactive",
            "unshare",
            "--net",
            "--",
            "setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
            "--",
            *map(str, argv),
        ]

    def run(self, phase: str, argv: Sequence[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        command = self.command_for(phase, argv)
        try:
            return subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeAcquisitionError(f"network-denied protected phase {phase!r} failed") from exc


class ExactRuntimeSession:
    """Disposable exact-runtime preparation gate for Graphify acceptance.

    Public construction is intentionally not parameterized: callers cannot substitute
    another runtime identity or alternate acquisition route. Tests exercise private
    helpers with miniature fixtures while this session remains bound to EXACT_CONTRACT.
    """

    def __init__(self, runner_temp: str | os.PathLike[str]):
        self.runner_temp = Path(runner_temp).resolve()
        self.install_root = self.runner_temp / INSTALL_DIRNAME
        self.scratch_root = self.runner_temp / SCRATCH_DIRNAME
        self.archive_path = self.scratch_root / ARTIFACT_FILENAME
        self.python: Path | None = None
        self.provenance: RuntimeProvenance | None = None
        self._network_executor: NetworkDeniedExecutor | None = None
        self._builder_timer_started: float | None = None

    def _assert_fresh_locations(self) -> None:
        if not self.runner_temp.is_dir():
            raise RuntimeAcquisitionError("RUNNER_TEMP must be an existing directory")
        if self.install_root.exists() or self.install_root.is_symlink():
            raise RuntimeAcquisitionError("task-local runtime target already exists")
        if self.scratch_root.exists() or self.scratch_root.is_symlink():
            raise RuntimeAcquisitionError("task-local acquisition scratch/cache target already exists")

    def prepare(self) -> "ExactRuntimeSession":
        if self.provenance is not None:
            raise RuntimeAcquisitionError("runtime session cannot be prepared twice")
        self._assert_fresh_locations()
        try:
            self.scratch_root.mkdir(mode=0o700)
            get = lambda url: _https_get(url)
            count, digest, redirects, final_host = _download_archive(
                self.archive_path,
                contract=EXACT_CONTRACT,
                get=get,
            )
            _extract_verified_archive(self.archive_path, self.install_root)
            python = _find_exact_python(self.install_root)
            report = _report_python(python)
            ready = time.monotonic()
            self.python = python
            self.provenance = RuntimeProvenance(
                artifact_url=ARTIFACT_URL,
                artifact_filename=ARTIFACT_FILENAME,
                artifact_bytes=count,
                artifact_sha256=digest,
                redirect_count=redirects,
                final_host=final_host,
                install_root=str(self.install_root),
                executable_report=report,
                runtime_ready_monotonic=ready,
            )
            return self
        except Exception:
            self.cleanup()
            raise

    def seal_network(self) -> NetworkDeniedExecutor:
        if self.provenance is None or self.python is None:
            raise RuntimeAcquisitionError("runtime must be verified before network shutdown")
        if self._builder_timer_started is not None:
            raise RuntimeAcquisitionError("network must be denied before builder timer starts")
        if self._network_executor is None:
            self._network_executor = NetworkDeniedExecutor(self.install_root)
        return self._network_executor

    def begin_builder_timer(self) -> float:
        if self.provenance is None:
            raise RuntimeAcquisitionError("runtime acquisition/setup must finish before builder timer")
        if self._network_executor is None:
            raise RuntimeAcquisitionError("network must be denied before builder timer")
        if self._builder_timer_started is not None:
            raise RuntimeAcquisitionError("builder timer cannot be started twice")
        started = time.monotonic()
        if started < self.provenance.runtime_ready_monotonic:
            raise RuntimeAcquisitionError("monotonic timer ordering violation")
        self._builder_timer_started = started
        return started

    @property
    def network_executor(self) -> NetworkDeniedExecutor:
        if self._network_executor is None:
            raise RuntimeAcquisitionError("network-denied executor has not been established")
        return self._network_executor

    def cleanup(self) -> None:
        shutil.rmtree(self.install_root, ignore_errors=True)
        shutil.rmtree(self.scratch_root, ignore_errors=True)
        self.python = None

    def __enter__(self) -> "ExactRuntimeSession":
        return self.prepare()

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.cleanup()
        return False
