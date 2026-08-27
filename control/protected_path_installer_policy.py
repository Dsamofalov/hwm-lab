#!/usr/bin/env python3
"""Fail-closed policy for the controlled protected-path installer."""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

from protected_path_installer_contract import (
    ALLOWED_AUTHOR,
    RESULT_SCHEMA,
    InstallFailure,
    is_sha,
    parse_transport_comment,
)

TASK_LINE_RE = re.compile(r"(?im)^Task id:\s*`([^`]+)`\s*$")
CLAIMED_BRANCH_RE = re.compile(r"(?im)^Claimed branch:\s*`([^`]+)`\s*$")
INSTALL_BRANCH_RE = re.compile(r"(?im)^Protected-path installation branch:\s*`([^`]+)`\s*$")
RUNTIME_SECTION = "## Runtime protected-path allowlist"
ACTION_PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")


def _load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = path or Path(__file__).with_name("protected_path_installer_manifest.bootstrap-v1.json")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema") != "hwm-protected-path-installer-manifest/bootstrap-v1":
        raise RuntimeError("trusted protected-path installer manifest schema mismatch")
    return data


def _normal_path(path: str) -> bool:
    if not path or path.startswith("/") or path.endswith("/") or "\\" in path or "//" in path:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in path):
        return False
    if unicodedata.normalize("NFC", path) != path:
        return False
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    if any(part.lower() == ".git" for part in parts):
        return False
    return PurePosixPath(path).as_posix() == path


def issue_task_id(body: Any) -> str | None:
    if not isinstance(body, str):
        return None
    values = TASK_LINE_RE.findall(body)
    return values[0] if len(values) == 1 else None


def issue_installation_branch(body: Any) -> str | None:
    if not isinstance(body, str):
        return None
    preferred = INSTALL_BRANCH_RE.findall(body)
    if len(preferred) == 1:
        return preferred[0]
    if preferred:
        return None
    claimed = CLAIMED_BRANCH_RE.findall(body)
    return claimed[0] if len(claimed) == 1 else None


def issue_declared_runtime_paths(body: Any) -> list[str]:
    if not isinstance(body, str):
        return []
    lines = body.splitlines()
    try:
        start = lines.index(RUNTIME_SECTION)
    except ValueError:
        return []
    paths: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("- `") and stripped.endswith("`"):
            paths.append(stripped[3:-1])
    if len(paths) != len(set(paths)) or any(not _normal_path(path) for path in paths):
        return []
    return paths


def validate_architecture_issue(issue: Any) -> None:
    if not isinstance(issue, dict) or issue.get("state") != "open":
        raise InstallFailure("ARCHITECTURE_ISSUE_NOT_CLAIMED", "architecture Issue must be open")
    labels = {item.get("name") if isinstance(item, dict) else item for item in issue.get("labels", [])}
    if "claimed" not in labels:
        raise InstallFailure("ARCHITECTURE_ISSUE_NOT_CLAIMED", "architecture Issue must be claimed")
    missing = {"architecture", "trusted", "contract"} - labels
    if missing:
        raise InstallFailure("REQUIRED_LABEL_MISSING", "architecture Issue is missing a required trusted-contract label")
    assignees = issue.get("assignees") or []
    if not any(
        isinstance(item, dict)
        and item.get("id") == ALLOWED_AUTHOR["github_account_id"]
        and item.get("login") == ALLOWED_AUTHOR["login"]
        for item in assignees
    ):
        raise InstallFailure("ARCHITECTURE_ISSUE_NOT_CLAIMED", "architecture Issue is not assigned to the exact owner")


def _looks_secret_or_environment(path: str) -> bool:
    low = path.lower()
    parts = [part.lower() for part in path.split("/")]
    sensitive = {
        "secret",
        "secrets",
        "environment",
        "environments",
        "credentials",
        "credential",
        "tokens",
        "token",
    }
    if any(part in sensitive for part in parts):
        return True
    return any(marker in low for marker in ("/.env", "secret-store", "credential-policy", "environment-policy"))


def _looks_ruleset_or_settings(path: str) -> bool:
    low = path.lower()
    parts = [part.lower() for part in path.split("/")]
    if any(part in {"rules", "ruleset", "rulesets", "settings", "repository-settings"} for part in parts):
        return True
    return low.startswith(".github/rulesets/") or low.startswith(".github/settings/")


def validate_protected_path(path: str, declared: list[str], manifest: dict[str, Any] | None = None) -> None:
    data = manifest or _load_manifest()
    low = path.lower() if isinstance(path, str) else ""
    base = low.rsplit("/", 1)[-1]
    if base == "codeowners":
        raise InstallFailure("CODEOWNERS_FORBIDDEN", "CODEOWNERS is outside protected-path installer authority")
    if _looks_ruleset_or_settings(path):
        raise InstallFailure("RULESET_OR_SETTINGS_FORBIDDEN", "ruleset or repository settings paths are forbidden")
    if _looks_secret_or_environment(path):
        raise InstallFailure("SECRET_OR_ENVIRONMENT_PATH_FORBIDDEN", "secret, credential, or environment paths are forbidden")
    if path in set(data.get("self_paths", [])) or low.startswith(".github/actions/protected-path-installer/"):
        raise InstallFailure("SELF_MODIFICATION_FORBIDDEN", "protected-path installer cannot modify itself")
    if path in set(data.get("ordinary_publisher_paths", [])) or low.startswith(".github/actions/task-branch-publisher/"):
        raise InstallFailure("ORDINARY_PUBLISHER_MODIFICATION_FORBIDDEN", "ordinary publisher trust surfaces are immutable to this installer")
    if path in set(data.get("bootstrap_workflow_paths", [])):
        raise InstallFailure("BOOTSTRAP_WORKFLOW_MODIFICATION_FORBIDDEN", "required repository bootstrap workflow is immutable")
    if not _normal_path(path):
        raise InstallFailure("PATH_CLASS_FORBIDDEN", "path normalization or traversal check failed")
    prefixes = tuple(data.get("allowed_path_prefixes", []))
    if not path.startswith(prefixes):
        raise InstallFailure("PATH_CLASS_FORBIDDEN", "path is outside the bootstrap-v1 protected path classes")
    if path not in declared:
        raise InstallFailure("UNDECLARED_PATH", "path is not exactly declared by the owning architecture Issue")


def preflight_concurrency(event: dict[str, Any]) -> dict[str, str]:
    comment = event.get("comment") if isinstance(event, dict) else None
    issue = event.get("issue") if isinstance(event, dict) else None
    if not isinstance(comment, dict) or not isinstance(issue, dict) or issue.get("pull_request"):
        return {"should_run": "false", "concurrency_key": "ignored"}
    user = comment.get("user") or {}
    if (
        user.get("id") != ALLOWED_AUTHOR["github_account_id"]
        or user.get("login") != ALLOWED_AUTHOR["login"]
        or comment.get("author_association") != ALLOWED_AUTHOR["author_association"]
    ):
        return {"should_run": "false", "concurrency_key": "unauthorized"}
    body = comment.get("body")
    branch: str | None = None
    try:
        kind, request = parse_transport_comment(body)
        if kind == "result":
            return {"should_run": "false", "concurrency_key": "result"}
        branch = request.get("installation_branch") if isinstance(request, dict) else None
    except InstallFailure:
        branch = None
    repo = ((event.get("repository") or {}).get("full_name") if isinstance(event.get("repository"), dict) else "") or "unknown"
    identity = branch if isinstance(branch, str) else f"invalid-comment-{comment.get('id', 'unknown')}"
    key = hashlib.sha256(f"{repo}\0{identity}".encode("utf-8")).hexdigest()[:32]
    return {"should_run": "true", "concurrency_key": key}


def _best_context(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {
            "request_id": "invalid-request",
            "repository": None,
            "architecture_issue": None,
            "task_id": None,
            "installation_branch": None,
            "expected_head": None,
            "protected_main_base_sha": None,
        }
    issue = obj.get("architecture_issue")
    return {
        "request_id": (obj.get("request_id") if isinstance(obj.get("request_id"), str) else "invalid-request")[:128] or "invalid-request",
        "repository": obj.get("repository") if isinstance(obj.get("repository"), str) else None,
        "architecture_issue": issue if isinstance(issue, int) and not isinstance(issue, bool) and issue > 0 else None,
        "task_id": obj.get("task_id") if isinstance(obj.get("task_id"), str) else None,
        "installation_branch": obj.get("installation_branch") if isinstance(obj.get("installation_branch"), str) else None,
        "expected_head": obj.get("expected_head") if is_sha(obj.get("expected_head")) else None,
        "protected_main_base_sha": obj.get("protected_main_base_sha") if is_sha(obj.get("protected_main_base_sha")) else None,
    }


def error_result(obj: Any, fingerprint: str, failure: InstallFailure, observed_head: str | None = None) -> dict[str, Any]:
    ctx = _best_context(obj)
    return {
        "schema": RESULT_SCHEMA,
        "request_id": ctx["request_id"],
        "status": "error",
        "repository": ctx["repository"],
        "architecture_issue": ctx["architecture_issue"],
        "task_id": ctx["task_id"],
        "installation_branch": ctx["installation_branch"],
        "expected_head": ctx["expected_head"],
        "protected_main_base_sha": ctx["protected_main_base_sha"],
        "observed_head_before": observed_head if is_sha(observed_head) else None,
        "request_fingerprint": fingerprint,
        "idempotent_replay": False,
        "error": {"code": failure.code, "message": failure.message, "retryable": failure.retryable},
    }


def _top_level_block(lines: list[str], key: str) -> list[str] | None:
    marker = f"{key}:"
    for index, line in enumerate(lines):
        if line == marker:
            block: list[str] = []
            for item in lines[index + 1 :]:
                if item and not item[0].isspace():
                    break
                block.append(item)
            return block
        if line.startswith(marker + " "):
            return [line[len(marker) :].strip()]
    return None


def validate_candidate_workflow(path: str, raw: bytes) -> None:
    if len(raw) > 512 * 1024 or b"\x00" in raw:
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow is not bounded UTF-8 text")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow is not UTF-8") from exc
    lowered = text.lower()
    for forbidden in ("pull_request_target", "${{ secrets.", "secrets:"):
        if forbidden in lowered:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow requests a forbidden trigger or secret surface")
    lines = text.splitlines()
    permissions = _top_level_block(lines, "permissions")
    normalized_permissions = [line.strip() for line in (permissions or []) if line.strip() and not line.lstrip().startswith("#")]
    if normalized_permissions != ["contents: read"]:
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow must declare top-level permissions contents: read only")
    trigger = _top_level_block(lines, "on")
    trigger_text = "\n".join(line.strip() for line in (trigger or []) if line.strip() and not line.lstrip().startswith("#"))
    if "workflow_dispatch:" not in trigger_text:
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow must be explicitly dispatchable")
    for forbidden_trigger in ("push:", "pull_request:", "issue_comment:", "schedule:", "repository_dispatch:", "workflow_run:"):
        if forbidden_trigger in trigger_text:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow trigger is outside bootstrap-v1 static policy")
    for line in lines:
        stripped = line.strip()
        if "uses:" not in stripped:
            continue
        value = stripped.split("uses:", 1)[1].strip().split(" #", 1)[0].strip().strip("'\"")
        if not ACTION_PIN_RE.fullmatch(value):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "every external Action use must be pinned to an exact 40-hex commit SHA")
    if re.search(r"(?im)^\s+[A-Za-z0-9_-]+:\s*write\s*(?:#.*)?$", text):
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate workflow may not request write permissions")
