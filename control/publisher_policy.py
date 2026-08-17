#!/usr/bin/env python3
"""Protected bootstrap-v1 publisher path, transport-preflight, and branch-local policy."""
from __future__ import annotations

import hashlib
import json
import threading
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

from publisher_contract import (
    ALLOWED_AUTHOR,
    RESULT_SCHEMA,
    RECORDED_BRANCH_RE,
    PublishFailure,
    _sha,
    parse_transport_comment,
)

_BRANCH_LOCKS: dict[tuple[str, str], threading.Lock] = {}
_BRANCH_LOCKS_GUARD = threading.Lock()

def preflight_concurrency(event: dict[str, Any]) -> dict[str, str]:
    """Return non-sensitive outputs for Actions branch-local concurrency grouping."""
    comment = event.get("comment") if isinstance(event, dict) else None
    issue = event.get("issue") if isinstance(event, dict) else None
    if not isinstance(comment, dict) or not isinstance(issue, dict) or issue.get("pull_request"):
        return {"should_run": "false", "concurrency_key": "ignored"}
    body = comment.get("body")
    try:
        kind, request = parse_transport_comment(body)
    except PublishFailure:
        request = None
        kind = "request"
    if kind == "result":
        return {"should_run": "false", "concurrency_key": "result"}
    author = comment.get("user") or {}
    if author.get("id") != ALLOWED_AUTHOR["github_account_id"] or author.get("login") != ALLOWED_AUTHOR["login"]:
        return {"should_run": "false", "concurrency_key": "unauthorized"}
    repo = ((event.get("repository") or {}).get("full_name") if isinstance(event.get("repository"), dict) else "") or "unknown"
    branch = request.get("task_branch") if isinstance(request, dict) else None
    if not isinstance(branch, str):
        branch = f"invalid-comment-{comment.get('id', 'unknown')}"
    key = hashlib.sha256(f"{repo}\0{branch}".encode("utf-8")).hexdigest()[:32]
    return {"should_run": "true", "concurrency_key": key}


def _branch_lock(key: tuple[str, str]) -> threading.Lock:
    with _BRANCH_LOCKS_GUARD:
        return _BRANCH_LOCKS.setdefault(key, threading.Lock())


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


def _load_manifest(path: Path | None = None) -> dict[str, Any]:
    manifest_path = path or Path(__file__).with_name("publisher_manifest.bootstrap-v1.json")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema") != "hwm-publisher-protected-paths/bootstrap-v1":
        raise RuntimeError("trusted publisher manifest schema mismatch")
    return data


def path_forbidden(path: str, manifest: dict[str, Any]) -> bool:
    if not _normal_path(path):
        return True
    low = path.lower()
    parts = path.split("/")
    base_low = parts[-1].lower()
    if low.startswith(".github/workflows/") or low.startswith(".github/actions/"):
        return True
    if base_low in {"action.yml", "action.yaml", "codeowners"}:
        return True
    if path in set(manifest.get("exact_paths", [])):
        return True
    return any(path.startswith(prefix) for prefix in manifest.get("prefixes", []))


def recorded_issue_branches(issue_body: Any) -> set[str]:
    if not isinstance(issue_body, str):
        return set()
    return {match for match in RECORDED_BRANCH_RE.findall(issue_body) if match.startswith("agent/infra-")}


def _best_context(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {"request_id": "invalid-request", "repository": None, "task_issue": None, "task_branch": None, "expected_head": None}
    rid = obj.get("request_id") if isinstance(obj.get("request_id"), str) else "invalid-request"
    return {
        "request_id": rid[:128] or "invalid-request",
        "repository": obj.get("repository") if isinstance(obj.get("repository"), str) else None,
        "task_issue": obj.get("task_issue") if isinstance(obj.get("task_issue"), int) and not isinstance(obj.get("task_issue"), bool) and obj.get("task_issue") > 0 else None,
        "task_branch": obj.get("task_branch") if isinstance(obj.get("task_branch"), str) else None,
        "expected_head": obj.get("expected_head") if _sha(obj.get("expected_head")) else None,
    }


def error_result(obj: Any, fingerprint: str, failure: PublishFailure, observed_head: str | None = None, replay: bool = False) -> dict[str, Any]:
    ctx = _best_context(obj)
    return {
        "schema": RESULT_SCHEMA,
        "request_id": ctx["request_id"],
        "status": "error",
        "repository": ctx["repository"],
        "task_issue": ctx["task_issue"],
        "task_branch": ctx["task_branch"],
        "expected_head": ctx["expected_head"],
        "observed_head_before": observed_head if _sha(observed_head) else None,
        "request_fingerprint": fingerprint,
        "idempotent_replay": replay,
        "error": {"code": failure.code, "message": failure.message, "retryable": failure.retryable},
    }


