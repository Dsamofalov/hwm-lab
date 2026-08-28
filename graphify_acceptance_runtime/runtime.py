from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import time
import unicodedata
from urllib.parse import urlsplit

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
SCRATCH_DIRNAME = "hwm-i10-0085-runtime-v2"
SETUP_TIMEOUT_SECONDS = 300
SEMANTIC_BUILDER_TIMEOUT_SECONDS = 900
PROTECTED_PHASES = ("artifact_setup", "product_parsing", "graphify_invocation")
CREDENTIALS_AUTHORIZED = False
PROTECTED_PATH_MUTATION_AUTHORIZED = False

_REDIRECTS = frozenset({301, 302, 303, 307, 308})
_DRIVE = re.compile(r"^[A-Za-z]:")
_ROOT_SENTINEL = "."


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


RUNTIME_CONTRACT = _RuntimeContract(
    url=ARTIFACT_URL,
    filename=ARTIFACT_FILENAME,
    size=ARTIFACT_BYTES,
    sha256=ARTIFACT_SHA256,
    redirect_host=FINAL_REDIRECT_HOST,
    executable_report=EXPECTED_REPORT,
)


_EXACT_SYMLINKS = (
    {
        "extract": True, "linkname": "2to3-3.12", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "2to3-3.12", "normalized_path": "bin/2to3", "raw_name": "./bin/2to3",
        "resolved_target": "bin/2to3-3.12", "size": 0, "tar_type": "2",
        "terminal_target": "bin/2to3-3.12", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "idle3.12", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "idle3.12", "normalized_path": "bin/idle3", "raw_name": "./bin/idle3",
        "resolved_target": "bin/idle3.12", "size": 0, "tar_type": "2",
        "terminal_target": "bin/idle3.12", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "pydoc3.12", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "pydoc3.12", "normalized_path": "bin/pydoc3", "raw_name": "./bin/pydoc3",
        "resolved_target": "bin/pydoc3.12", "size": 0, "tar_type": "2",
        "terminal_target": "bin/pydoc3.12", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "python3.12", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "python3.12", "normalized_path": "bin/python3", "raw_name": "./bin/python3",
        "resolved_target": "bin/python3.12", "size": 0, "tar_type": "2",
        "terminal_target": "bin/python3.12", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "python3.12-config", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "python3.12-config", "normalized_path": "bin/python3-config",
        "raw_name": "./bin/python3-config", "resolved_target": "bin/python3.12-config", "size": 0,
        "tar_type": "2", "terminal_target": "bin/python3.12-config", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "libpython3.12.so.1.0", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "libpython3.12.so.1.0", "normalized_path": "lib/libpython3.12.so",
        "raw_name": "./lib/libpython3.12.so", "resolved_target": "lib/libpython3.12.so.1.0", "size": 0,
        "tar_type": "2", "terminal_target": "lib/libpython3.12.so.1.0", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "python-3.12-embed.pc", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "python-3.12-embed.pc", "normalized_path": "lib/pkgconfig/python3-embed.pc",
        "raw_name": "./lib/pkgconfig/python3-embed.pc", "resolved_target": "lib/pkgconfig/python-3.12-embed.pc",
        "size": 0, "tar_type": "2", "terminal_target": "lib/pkgconfig/python-3.12-embed.pc",
        "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "python-3.12.pc", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "python-3.12.pc", "normalized_path": "lib/pkgconfig/python3.pc",
        "raw_name": "./lib/pkgconfig/python3.pc", "resolved_target": "lib/pkgconfig/python-3.12.pc", "size": 0,
        "tar_type": "2", "terminal_target": "lib/pkgconfig/python-3.12.pc", "terminal_target_type": "regular",
    },
    {
        "extract": True, "linkname": "python3.12.1", "member_type": "symlink", "mode": 511,
        "normalized_linkname": "python3.12.1", "normalized_path": "share/man/man1/python3.1",
        "raw_name": "./share/man/man1/python3.1", "resolved_target": "share/man/man1/python3.12.1", "size": 0,
        "tar_type": "2", "terminal_target": "share/man/man1/python3.12.1", "terminal_target_type": "regular",
    },
)

_EXACT_ROOT_SENTINEL = {
    "extract": False,
    "linkname": "",
    "member_type": "archive_root_sentinel",
    "mode": 493,
    "normalized_path": None,
    "raw_name": ".",
    "size": 0,
    "tar_type": "5",
}


@dataclass(frozen=True)
class _ArchiveLayoutContract:
    canonical_inventory_sha256: str
    canonical_inventory_bytes: int
    total_member_count: int
    archive_root_sentinel_count: int
    directory_count: int
    regular_count: int
    symlink_count: int
    hardlink_count: int
    special_count: int
    root_sentinel: dict[str, object]
    symlinks: tuple[dict[str, object], ...]

    @property
    def counts(self) -> dict[str, int]:
        return {
            "total_member_count": self.total_member_count,
            "archive_root_sentinel_count": self.archive_root_sentinel_count,
            "directory_count": self.directory_count,
            "regular_count": self.regular_count,
            "symlink_count": self.symlink_count,
            "hardlink_count": self.hardlink_count,
            "special_count": self.special_count,
        }


EXACT_LAYOUT = _ArchiveLayoutContract(
    canonical_inventory_sha256="266fbc38be6ffdc9c565953d44cc208e74d6db8a2f038186580fd4904279f3db",
    canonical_inventory_bytes=2361714,
    total_member_count=9341,
    archive_root_sentinel_count=1,
    directory_count=447,
    regular_count=8884,
    symlink_count=9,
    hardlink_count=0,
    special_count=0,
    root_sentinel=_EXACT_ROOT_SENTINEL,
    symlinks=_EXACT_SYMLINKS,
)


@dataclass(frozen=True)
class _InventoryRecord:
    raw_name: str
    normalized_path: str
    member_type: str
    tar_type: str
    mode: int
    size: int
    linkname: str
    extract: bool
    normalized_linkname: str | None = None
    resolved_target: str | None = None
    terminal_target: str | None = None
    terminal_target_type: str | None = None

    def canonical_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "raw_name": self.raw_name,
            "normalized_path": self.normalized_path,
            "member_type": self.member_type,
            "tar_type": self.tar_type,
            "mode": self.mode,
            "size": self.size,
            "linkname": self.linkname,
            "extract": self.extract,
        }
        if self.normalized_linkname is not None:
            result["normalized_linkname"] = self.normalized_linkname
            result["resolved_target"] = self.resolved_target
        return result

    def allowlist_dict(self) -> dict[str, object]:
        result = self.canonical_dict()
        if self.member_type in {"symlink", "hardlink"}:
            result["terminal_target"] = self.terminal_target
            result["terminal_target_type"] = self.terminal_target_type
        return result


@dataclass(frozen=True)
class ArchiveInventory:
    root_sentinel: dict[str, object]
    records: tuple[_InventoryRecord, ...]
    canonical_bytes: int
    canonical_sha256: str
    counts: dict[str, int]
    symlinks: tuple[dict[str, object], ...]
    hardlinks: tuple[dict[str, object], ...]
    specials: tuple[dict[str, object], ...]

    @property
    def by_path(self) -> dict[str, _InventoryRecord]:
        return {record.normalized_path: record for record in self.records}


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
    canonical_inventory_sha256: str
    canonical_inventory_bytes: int
    inventory_counts: dict[str, int]
    symlinks: tuple[tuple[str, str, str], ...]
    runtime_ready_monotonic: float


def _has_control(value: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" for ch in value)


def _validate_text(raw: str, *, context: str) -> None:
    if not raw or raw.startswith("/") or _DRIVE.match(raw) or "\\" in raw or _has_control(raw):
        raise RuntimeAcquisitionError(f"unsafe {context}: {raw!r}")
    if unicodedata.normalize("NFC", raw) != raw:
        raise RuntimeAcquisitionError(f"non-NFC {context}: {raw!r}")


def _normalize_member_path(raw: str, *, member_type: str) -> str:
    _validate_text(raw, context="archive member path")
    value = raw
    if value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("./"):
        raise RuntimeAcquisitionError(f"unsafe archive member transport prefix: {raw!r}")
    _validate_text(value, context="archive member path after transport normalization")
    if value.endswith("/"):
        if member_type != "directory":
            raise RuntimeAcquisitionError(f"trailing slash on non-directory archive member: {raw!r}")
        value = value[:-1]
        if not value or value.endswith("/"):
            raise RuntimeAcquisitionError(f"unsafe repeated directory trailing slash: {raw!r}")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAcquisitionError(f"unsafe archive member segment: {raw!r}")
    return "/".join(parts)


def _normalize_linkname(raw: str) -> str:
    _validate_text(raw, context="archive linkname")
    value = raw
    if value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("./"):
        raise RuntimeAcquisitionError(f"unsafe archive linkname transport prefix: {raw!r}")
    _validate_text(value, context="archive linkname after transport normalization")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAcquisitionError(f"unsafe archive linkname segment: {raw!r}")
    return "/".join(parts)


def _resolve_symlink_target(path: str, normalized_linkname: str) -> str:
    parent = path.split("/")[:-1]
    target = parent + normalized_linkname.split("/")
    if not target or any(part in {"", ".", ".."} for part in target):
        raise RuntimeAcquisitionError(f"unsafe resolved symlink target: {path!r} -> {normalized_linkname!r}")
    return "/".join(target)


def _member_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.isfile():
        return "regular"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "special"


def _tar_type(member: tarfile.TarInfo) -> str:
    value = member.type
    return value.decode("latin-1") if isinstance(value, bytes) else str(value)


def _root_sentinel_record(member: tarfile.TarInfo) -> dict[str, object]:
    if member.name != _ROOT_SENTINEL or not member.isdir() or member.size != 0 or member.linkname != "":
        raise RuntimeAcquisitionError("exact archive root sentinel is malformed")
    if member.issym() or member.islnk():
        raise RuntimeAcquisitionError("exact archive root sentinel may not be a link")
    return {
        "raw_name": ".",
        "member_type": "archive_root_sentinel",
        "tar_type": _tar_type(member),
        "mode": member.mode,
        "size": 0,
        "linkname": "",
        "normalized_path": None,
        "extract": False,
    }


def _scan_inventory(
    archive_path: Path,
    *,
    reject_hardlinks: bool = False,
    reject_specials: bool = False,
) -> ArchiveInventory:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        members = archive.getmembers()

    root: dict[str, object] | None = None
    root_count = 0
    records: list[_InventoryRecord] = []
    seen: dict[str, str] = {}

    for member in members:
        if member.name == _ROOT_SENTINEL:
            root_count += 1
            if root_count != 1:
                raise RuntimeAcquisitionError("exact archive root sentinel appears more than once")
            root = _root_sentinel_record(member)
            continue

        kind = _member_type(member)
        if kind == "hardlink" and reject_hardlinks:
            raise RuntimeAcquisitionError(f"hardlink archive member is forbidden: {member.name!r}")
        if kind == "special" and reject_specials:
            raise RuntimeAcquisitionError(f"special archive member is forbidden: {member.name!r}")
        path = _normalize_member_path(member.name, member_type=kind)
        if path in seen:
            raise RuntimeAcquisitionError(
                f"duplicate canonical archive path: {path!r} from {seen[path]!r} and {member.name!r}"
            )
        seen[path] = member.name

        normalized_linkname = None
        resolved_target = None
        if kind in {"symlink", "hardlink"}:
            normalized_linkname = _normalize_linkname(member.linkname)
            resolved_target = (
                _resolve_symlink_target(path, normalized_linkname)
                if kind == "symlink" else normalized_linkname
            )

        records.append(
            _InventoryRecord(
                raw_name=member.name,
                normalized_path=path,
                member_type=kind,
                tar_type=_tar_type(member),
                mode=member.mode,
                size=member.size,
                linkname=member.linkname,
                extract=kind in {"directory", "regular", "symlink", "hardlink"},
                normalized_linkname=normalized_linkname,
                resolved_target=resolved_target,
            )
        )

    if root_count != 1 or root is None:
        raise RuntimeAcquisitionError(f"exact archive must contain one root sentinel; count={root_count}")

    records.sort(key=lambda item: (item.normalized_path, item.member_type, item.raw_name))
    by_path = {item.normalized_path: item for item in records}

    for item in records:
        parts = item.normalized_path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            parent_record = by_path.get(parent)
            if parent_record is None or parent_record.member_type != "directory":
                raise RuntimeAcquisitionError(
                    f"archive member parent is not an explicit real directory: {item.normalized_path!r} -> {parent!r}"
                )

    def terminal(path: str, stack: tuple[str, ...] = ()) -> tuple[str, str]:
        if path not in by_path:
            raise RuntimeAcquisitionError(f"dangling archive link target: {path!r}")
        if path in stack:
            raise RuntimeAcquisitionError("archive link cycle: " + " -> ".join(stack + (path,)))
        item = by_path[path]
        if item.member_type in {"symlink", "hardlink"}:
            assert item.resolved_target is not None
            return terminal(item.resolved_target, stack + (path,))
        if item.member_type == "special":
            raise RuntimeAcquisitionError(f"archive link resolves to special member: {path!r}")
        if item.member_type not in {"regular", "directory"}:
            raise RuntimeAcquisitionError(f"unsupported archive link terminal type: {item.member_type!r}")
        return path, item.member_type

    updated: list[_InventoryRecord] = []
    symlinks: list[dict[str, object]] = []
    hardlinks: list[dict[str, object]] = []
    specials: list[dict[str, object]] = []
    for item in records:
        if item.member_type in {"symlink", "hardlink"}:
            terminal_path, terminal_type = terminal(item.normalized_path)
            item = _InventoryRecord(**{
                **item.__dict__,
                "terminal_target": terminal_path,
                "terminal_target_type": terminal_type,
            })
            if item.member_type == "symlink":
                symlinks.append(item.allowlist_dict())
            else:
                hardlinks.append(item.allowlist_dict())
        elif item.member_type == "special":
            specials.append(item.canonical_dict())
        updated.append(item)
    records = updated

    canonical = json.dumps(
        [root, *[item.canonical_dict() for item in records]],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    counts = {
        "total_member_count": 1 + len(records),
        "archive_root_sentinel_count": root_count,
        "directory_count": sum(item.member_type == "directory" for item in records),
        "regular_count": sum(item.member_type == "regular" for item in records),
        "symlink_count": len(symlinks),
        "hardlink_count": len(hardlinks),
        "special_count": len(specials),
    }
    return ArchiveInventory(
        root_sentinel=root,
        records=tuple(records),
        canonical_bytes=len(canonical),
        canonical_sha256=hashlib.sha256(canonical).hexdigest(),
        counts=counts,
        symlinks=tuple(symlinks),
        hardlinks=tuple(hardlinks),
        specials=tuple(specials),
    )


def _validate_exact_inventory(
    archive_path: Path,
    *,
    layout: _ArchiveLayoutContract = EXACT_LAYOUT,
) -> ArchiveInventory:
    inventory = _scan_inventory(archive_path, reject_hardlinks=True, reject_specials=True)
    if inventory.canonical_bytes != layout.canonical_inventory_bytes:
        raise RuntimeAcquisitionError(
            f"canonical inventory byte-size drift: {inventory.canonical_bytes} != {layout.canonical_inventory_bytes}"
        )
    if inventory.canonical_sha256 != layout.canonical_inventory_sha256:
        raise RuntimeAcquisitionError(
            f"canonical inventory SHA-256 drift: {inventory.canonical_sha256}"
        )
    if inventory.counts != layout.counts:
        raise RuntimeAcquisitionError(f"canonical inventory count drift: {inventory.counts!r}")
    if inventory.root_sentinel != layout.root_sentinel:
        raise RuntimeAcquisitionError("archive root sentinel identity drift")
    if inventory.symlinks != layout.symlinks:
        raise RuntimeAcquisitionError("exact symlink allowlist identity drift")
    if inventory.hardlinks:
        raise RuntimeAcquisitionError("hardlink archive members are forbidden for exact artifact")
    if inventory.specials:
        raise RuntimeAcquisitionError("special archive members are forbidden for exact artifact")
    return inventory


def _path_from_canonical(root: Path, canonical: str) -> Path:
    parts = canonical.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise RuntimeAcquisitionError(f"invalid canonical path: {canonical!r}")
    return root.joinpath(*parts)


def _assert_real_parent(root: Path, target: Path) -> None:
    root_resolved = root.resolve(strict=True)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise RuntimeAcquisitionError(f"target escapes install root: {target}") from exc
    current = root
    for part in target.relative_to(root).parts[:-1]:
        current = current / part
        if not os.path.lexists(current) or current.is_symlink() or not current.is_dir():
            raise RuntimeAcquisitionError(f"filesystem parent is not a real directory: {current}")
        try:
            current.resolve(strict=True).relative_to(root_resolved)
        except ValueError as exc:
            raise RuntimeAcquisitionError(f"filesystem parent escapes install root: {current}") from exc


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise RuntimeAcquisitionError("bounded archive setup timeout exceeded")


def _safe_remove(path: Path) -> None:
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_dir():
        path.unlink()
    else:
        shutil.rmtree(path)


def _extract_verified_archive(
    archive_path: Path,
    install_root: Path,
    *,
    layout: _ArchiveLayoutContract = EXACT_LAYOUT,
    timeout: int = SETUP_TIMEOUT_SECONDS,
) -> ArchiveInventory:
    inventory = _validate_exact_inventory(archive_path, layout=layout)
    if os.path.lexists(install_root):
        raise RuntimeAcquisitionError(f"runtime install target already exists: {install_root}")

    deadline = time.monotonic() + timeout
    install_root.mkdir(mode=0o755)
    try:
        _check_deadline(deadline)
        by_raw: dict[str, tarfile.TarInfo]
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            by_raw = {member.name: member for member in members}

            directories = sorted(
                (item for item in inventory.records if item.member_type == "directory"),
                key=lambda item: (item.normalized_path.count("/"), item.normalized_path),
            )
            regulars = sorted(
                (item for item in inventory.records if item.member_type == "regular"),
                key=lambda item: by_raw[item.raw_name].offset,
            )

            for item in directories:
                _check_deadline(deadline)
                target = _path_from_canonical(install_root, item.normalized_path)
                _assert_real_parent(install_root, target)
                if os.path.lexists(target):
                    raise RuntimeAcquisitionError(f"archive extraction would overwrite existing entry: {item.normalized_path}")
                target.mkdir(mode=item.mode & 0o777)
                os.chmod(target, item.mode & 0o777)

            for item in regulars:
                _check_deadline(deadline)
                target = _path_from_canonical(install_root, item.normalized_path)
                _assert_real_parent(install_root, target)
                if os.path.lexists(target):
                    raise RuntimeAcquisitionError(f"archive extraction would overwrite existing entry: {item.normalized_path}")
                member = by_raw.get(item.raw_name)
                if member is None or not member.isfile():
                    raise RuntimeAcquisitionError(f"regular archive member disappeared: {item.raw_name!r}")
                source = archive.extractfile(member)
                if source is None:
                    raise RuntimeAcquisitionError(f"regular archive member has no payload: {item.raw_name!r}")
                written = 0
                with source, target.open("xb") as stream:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > item.size:
                            raise RuntimeAcquisitionError(f"regular archive member exceeded declared size: {item.raw_name!r}")
                        stream.write(chunk)
                        _check_deadline(deadline)
                if written != item.size:
                    raise RuntimeAcquisitionError(
                        f"regular archive member payload size drift: {item.raw_name!r}: {written} != {item.size}"
                    )
                os.chmod(target, item.mode & 0o777)

        for item in (record for record in inventory.records if record.member_type == "symlink"):
            _check_deadline(deadline)
            target = _path_from_canonical(install_root, item.normalized_path)
            _assert_real_parent(install_root, target)
            if os.path.lexists(target):
                raise RuntimeAcquisitionError(f"archive link would overwrite existing entry: {item.normalized_path}")
            assert item.normalized_linkname is not None
            assert item.terminal_target is not None
            terminal = _path_from_canonical(install_root, item.terminal_target)
            if not os.path.lexists(terminal) or terminal.is_symlink() or not terminal.is_file():
                raise RuntimeAcquisitionError(f"allowlisted symlink terminal is not a real regular file: {item.normalized_path}")
            os.symlink(item.normalized_linkname, target)

        _verify_extracted_inventory(install_root, inventory)
        _check_deadline(deadline)
        return inventory
    except Exception:
        _safe_remove(install_root)
        raise


def _actual_entries(root: Path) -> dict[str, os.DirEntry[str]]:
    result: dict[str, os.DirEntry[str]] = {}

    def walk(directory: Path, prefix: tuple[str, ...]) -> None:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                relative = "/".join((*prefix, entry.name))
                result[relative] = entry
                if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                    walk(Path(entry.path), (*prefix, entry.name))

    walk(root, ())
    return result


def _verify_extracted_inventory(root: Path, inventory: ArchiveInventory) -> None:
    if not os.path.lexists(root) or root.is_symlink() or not root.is_dir():
        raise RuntimeAcquisitionError("install root is not a real directory")
    expected = {item.normalized_path: item for item in inventory.records if item.extract}
    actual = _actual_entries(root)
    unexpected = sorted(set(actual) - set(expected))
    missing = sorted(set(expected) - set(actual))
    if unexpected:
        raise RuntimeAcquisitionError(f"unexpected post-extraction entries: {unexpected[:5]!r}")
    if missing:
        raise RuntimeAcquisitionError(f"missing post-extraction entries: {missing[:5]!r}")

    root_resolved = root.resolve(strict=True)
    for path, item in expected.items():
        target = _path_from_canonical(root, path)
        st = target.lstat()
        if item.member_type == "directory":
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                raise RuntimeAcquisitionError(f"directory identity drift after extraction: {path}")
            if stat.S_IMODE(st.st_mode) != (item.mode & 0o777):
                raise RuntimeAcquisitionError(f"directory mode drift after extraction: {path}")
            resolved = target.resolve(strict=True)
        elif item.member_type == "regular":
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                raise RuntimeAcquisitionError(f"regular identity drift after extraction: {path}")
            if st.st_size != item.size:
                raise RuntimeAcquisitionError(f"regular size drift after extraction: {path}")
            if stat.S_IMODE(st.st_mode) != (item.mode & 0o777):
                raise RuntimeAcquisitionError(f"regular mode drift after extraction: {path}")
            resolved = target.resolve(strict=True)
        elif item.member_type == "symlink":
            if not stat.S_ISLNK(st.st_mode):
                raise RuntimeAcquisitionError(f"symlink identity drift after extraction: {path}")
            assert item.normalized_linkname is not None
            if os.readlink(target) != item.normalized_linkname:
                raise RuntimeAcquisitionError(f"symlink linkname drift after extraction: {path}")
            try:
                resolved = target.resolve(strict=True)
            except (FileNotFoundError, RuntimeError) as exc:
                raise RuntimeAcquisitionError(f"dangling or cyclic symlink after extraction: {path}") from exc
            assert item.terminal_target is not None
            if resolved != _path_from_canonical(root, item.terminal_target).resolve(strict=True):
                raise RuntimeAcquisitionError(f"symlink terminal drift after extraction: {path}")
            if not resolved.is_file():
                raise RuntimeAcquisitionError(f"symlink terminal is not regular after extraction: {path}")
        else:
            raise RuntimeAcquisitionError(f"unexpected extracted member type: {item.member_type}")
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise RuntimeAcquisitionError(f"post-extraction root escape: {path}") from exc


class _ManagedResponse:
    def __init__(self, connection: http.client.HTTPSConnection, response: http.client.HTTPResponse):
        self._connection = connection
        self._response = response
        self.status = response.status

    def getheader(self, name: str):
        return self._response.getheader(name)

    def read(self, amount: int = -1):
        return self._response.read(amount)

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._connection.close()


def _https_get(
    url: str,
    *,
    connection_factory=http.client.HTTPSConnection,
):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise RuntimeAcquisitionError("runtime acquisition URL must be anonymous HTTPS")
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    connection = connection_factory(parsed.hostname, parsed.port or 443, timeout=30)
    headers = {
        "Accept": "application/octet-stream",
        "User-Agent": "hwm-i10-0085-runtime-v2/1",
    }
    connection.request("GET", target, headers=headers)
    return _ManagedResponse(connection, connection.getresponse())


def _download_archive(
    destination: Path,
    *,
    contract: _RuntimeContract = RUNTIME_CONTRACT,
    get=_https_get,
) -> tuple[int, str, int, str]:
    initial = urlsplit(contract.url)
    if (
        initial.scheme != "https"
        or initial.hostname != "github.com"
        or initial.username
        or initial.password
        or PurePosixPath(initial.path).name != contract.filename
    ):
        raise RuntimeAcquisitionError("initial artifact identity mismatch")
    if os.path.lexists(destination):
        raise RuntimeAcquisitionError(f"artifact destination already exists: {destination}")

    first = get(contract.url)
    try:
        if first.status not in _REDIRECTS:
            raise RuntimeAcquisitionError(f"exact artifact URL did not return the expected single redirect: HTTP {first.status}")
        location = first.getheader("Location")
        if not location:
            raise RuntimeAcquisitionError("artifact redirect omitted Location")
        redirected = urlsplit(location)
        if (
            redirected.scheme != "https"
            or redirected.hostname != contract.redirect_host
            or redirected.username
            or redirected.password
        ):
            raise RuntimeAcquisitionError(f"unexpected artifact redirect host: {redirected.hostname!r}")
        first.read()
    finally:
        first.close()

    second = get(location)
    try:
        if second.status in _REDIRECTS:
            raise RuntimeAcquisitionError("artifact acquisition exceeded one redirect")
        if second.status != 200:
            raise RuntimeAcquisitionError(f"artifact returned HTTP {second.status}")
        declared = second.getheader("Content-Length")
        try:
            declared_size = int(declared) if declared is not None else None
        except ValueError as exc:
            raise RuntimeAcquisitionError(f"unexpected artifact Content-Length: {declared!r}") from exc
        if declared_size != contract.size:
            raise RuntimeAcquisitionError(f"unexpected artifact Content-Length: {declared!r}")

        digest = hashlib.sha256()
        count = 0
        try:
            with destination.open("xb") as stream:
                while True:
                    chunk = second.read(1024 * 1024)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > contract.size:
                        raise RuntimeAcquisitionError("artifact exceeded exact byte count")
                    stream.write(chunk)
                    digest.update(chunk)
            actual_hash = digest.hexdigest()
            if count != contract.size:
                raise RuntimeAcquisitionError(f"artifact byte count mismatch: {count}")
            if actual_hash != contract.sha256:
                raise RuntimeAcquisitionError(f"artifact SHA-256 mismatch: {actual_hash}")
            return count, actual_hash, 1, contract.redirect_host
        except Exception:
            if os.path.lexists(destination):
                destination.unlink()
            raise
    finally:
        second.close()


def _find_exact_python(install_root: Path) -> Path:
    candidate = install_root / "bin" / "python3.12"
    if not os.path.lexists(candidate):
        raise RuntimeAcquisitionError("verified archive does not contain bin/python3.12")
    st = candidate.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise RuntimeAcquisitionError("bin/python3.12 is not a real regular file")
    return candidate


def _runtime_environment(install_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment["LD_LIBRARY_PATH"] = str(install_root / "lib")
    environment["PYTHONHOME"] = str(install_root)
    environment["PYTHONNOUSERSITE"] = "1"
    return environment


def _report_python(python: Path) -> str:
    install_root = python.parent.parent
    try:
        result = subprocess.run(
            [str(python), "-c", "import platform; print(platform.python_implementation(), platform.python_version())"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=_runtime_environment(install_root),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeAcquisitionError(f"verified runtime executable failed: {exc}") from exc
    report = result.stdout.strip()
    if report != EXPECTED_REPORT:
        raise RuntimeAcquisitionError(f"runtime executable report mismatch: {report!r}")
    return report


class NetworkDeniedExecutor:
    def __init__(self, install_root):
        self.install_root = Path(install_root)
        self.network_denied = True

    def command_for(self, phase: str, command: list[str]) -> list[str]:
        if phase not in PROTECTED_PHASES:
            raise RuntimeAcquisitionError(f"unknown protected execution phase: {phase}")
        if not command:
            raise RuntimeAcquisitionError("empty protected execution command")
        uid = os.getuid()
        gid = os.getgid()
        return [
            "sudo", "--non-interactive", "unshare", "--net", "--",
            "setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups",
            "--no-new-privs", "--",
            "/usr/bin/env",
            f"LD_LIBRARY_PATH={self.install_root / 'lib'}",
            f"PYTHONHOME={self.install_root}",
            "PYTHONNOUSERSITE=1",
            *command,
        ]

    def run(self, phase: str, command: list[str], *, timeout: int):
        return subprocess.run(
            self.command_for(phase, command),
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )


class ExactRuntimeSession:
    def __init__(self, runner_temp):
        self.runner_temp = Path(runner_temp).resolve()
        if not self.runner_temp.is_dir() or self.runner_temp.is_symlink():
            raise RuntimeAcquisitionError("RUNNER_TEMP must resolve to a real directory")
        self.install_root = self.runner_temp / INSTALL_DIRNAME
        self.scratch_root = self.runner_temp / SCRATCH_DIRNAME
        self.python: Path | None = None
        self.provenance: RuntimeProvenance | None = None
        self._network_executor: NetworkDeniedExecutor | None = None

    def _assert_fresh(self) -> None:
        for target in (self.install_root, self.scratch_root):
            if os.path.lexists(target):
                raise RuntimeAcquisitionError(f"preexisting runtime/cache target is forbidden: {target}")

    def prepare(self) -> None:
        self._assert_fresh()
        self.scratch_root.mkdir(mode=0o700)
        archive_path = self.scratch_root / ARTIFACT_FILENAME
        try:
            artifact_bytes, artifact_sha256, redirects, final_host = _download_archive(archive_path)
            inventory = _extract_verified_archive(archive_path, self.install_root)
            python = _find_exact_python(self.install_root)
            report = _report_python(python)
            ready = time.monotonic()
            self.python = python
            self.provenance = RuntimeProvenance(
                artifact_url=ARTIFACT_URL,
                artifact_filename=ARTIFACT_FILENAME,
                artifact_bytes=artifact_bytes,
                artifact_sha256=artifact_sha256,
                redirect_count=redirects,
                final_host=final_host,
                install_root=str(self.install_root),
                executable_report=report,
                canonical_inventory_sha256=inventory.canonical_sha256,
                canonical_inventory_bytes=inventory.canonical_bytes,
                inventory_counts=dict(inventory.counts),
                symlinks=tuple(
                    (str(item["normalized_path"]), str(item["linkname"]), str(item["terminal_target"]))
                    for item in inventory.symlinks
                ),
                runtime_ready_monotonic=ready,
            )
        except Exception:
            self.cleanup()
            raise

    def seal_network(self) -> NetworkDeniedExecutor:
        if self.provenance is None or self.python is None:
            raise RuntimeAcquisitionError("runtime must be ready before network denial")
        self._network_executor = NetworkDeniedExecutor(self.install_root)
        return self._network_executor

    def begin_builder_timer(self) -> float:
        if self.provenance is None or self.python is None:
            raise RuntimeAcquisitionError("runtime must be ready before builder timer")
        if self._network_executor is None or not self._network_executor.network_denied:
            raise RuntimeAcquisitionError("network must be denied before semantic builder timer")
        started = time.monotonic()
        if started < self.provenance.runtime_ready_monotonic:
            raise RuntimeAcquisitionError("builder timer began before runtime was ready")
        return started

    def cleanup(self) -> None:
        for target in (self.install_root, self.scratch_root):
            try:
                target.relative_to(self.runner_temp)
            except ValueError as exc:
                raise RuntimeAcquisitionError("cleanup target escaped RUNNER_TEMP") from exc
            _safe_remove(target)
        self.python = None
        self._network_executor = None

    def __enter__(self):
        self.prepare()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
        return False
