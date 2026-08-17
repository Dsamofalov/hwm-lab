#!/usr/bin/env python3
"""bootstrap-v1 publisher transport contract and normalized result primitives."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REQUEST_SCHEMA = "hwm-publish-request/bootstrap-v1"
RESULT_SCHEMA = "hwm-publish-result/bootstrap-v1"
ALLOWED_REPOSITORY = "Dsamofalov/hwm-lab"
ALLOWED_WORKFLOW = "infrastructure-ci.yml"
ALLOWED_AUTHOR = {"github_account_id": 25666939, "login": "Dsamofalov"}
PUBLISHER_RESULT_AUTHOR = {"github_account_id": 41898282, "login": "github-actions[bot]"}
REGULAR_MODES = {"100644", "100755"}
ERROR_CODES = {
    "INVALID_SCHEMA", "UNAUTHORIZED_AUTHOR", "REPOSITORY_NOT_ALLOWED", "TASK_NOT_CLAIMED",
    "BRANCH_TASK_MISMATCH", "EXPECTED_HEAD_MISMATCH", "FORBIDDEN_TARGET", "FORBIDDEN_PATH",
    "PATH_STATE_MISMATCH", "BLOB_NOT_FOUND", "BLOB_NOT_REGULAR", "REQUEST_ID_REUSE",
    "CI_DISPATCH_FAILED", "INTERNAL_ERROR",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQ_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
INFRA_BRANCH_RE = re.compile(r"^agent/infra-(\d{4})-[a-z0-9][a-z0-9-]{0,95}$")
RECORDED_BRANCH_RE = re.compile(r"(?im)\bbranch\s*:\s*`([^`]+)`")
PUBLISH_RESULT_MAX_MESSAGE = 240

class PublishFailure(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        if code not in ERROR_CODES:
            code = "INTERNAL_ERROR"
            message = "publisher rejected an unclassified failure"
            retryable = False
        super().__init__(message)
        self.code = code
        self.message = _sanitize_message(message)
        self.retryable = bool(retryable)


def _sanitize_message(message: str) -> str:
    text = " ".join(str(message).replace("\r", " ").replace("\n", " ").split())
    lowered = text.lower()
    for sensitive in ("authorization:", "bearer ", "token=", "private key", "cookie:"):
        if sensitive in lowered:
            return "sanitized publisher diagnostic"
    return text[:PUBLISH_RESULT_MAX_MESSAGE] or "publisher failure"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def request_fingerprint(request: Any) -> str:
    try:
        raw = canonical_json(request).encode("utf-8")
    except Exception:
        raw = repr(request).encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def _sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def validate_request_shape(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise PublishFailure("INVALID_SCHEMA", "request envelope must be one JSON object")
    top = {"schema", "request_id", "repository", "task_issue", "task_branch", "expected_head", "changes", "ci"}
    if set(obj) != top or obj.get("schema") != REQUEST_SCHEMA:
        raise PublishFailure("INVALID_SCHEMA", "request fields or schema do not match bootstrap-v1")
    if not isinstance(obj.get("request_id"), str) or REQ_ID_RE.fullmatch(obj["request_id"]) is None:
        raise PublishFailure("INVALID_SCHEMA", "request_id is invalid")
    if not isinstance(obj.get("repository"), str) or REPO_RE.fullmatch(obj["repository"]) is None:
        raise PublishFailure("INVALID_SCHEMA", "repository identity is malformed")
    if not isinstance(obj.get("task_issue"), int) or isinstance(obj["task_issue"], bool) or obj["task_issue"] < 1:
        raise PublishFailure("INVALID_SCHEMA", "task_issue must be a positive integer")
    if (
        not isinstance(obj.get("task_branch"), str)
        or not (1 <= len(obj["task_branch"]) <= 200)
        or obj["task_branch"].strip() != obj["task_branch"]
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in obj["task_branch"])
        or obj["task_branch"].startswith("/")
        or obj["task_branch"].endswith("/")
        or "//" in obj["task_branch"]
    ):
        raise PublishFailure("INVALID_SCHEMA", "task_branch is malformed")
    if not _sha(obj.get("expected_head")):
        raise PublishFailure("INVALID_SCHEMA", "expected_head must be an exact lowercase 40-hex SHA")
    changes = obj.get("changes")
    if not isinstance(changes, list) or not (1 <= len(changes) <= 64):
        raise PublishFailure("INVALID_SCHEMA", "changes must contain one to 64 operations")
    seen_paths: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            raise PublishFailure("INVALID_SCHEMA", "each change must be an object")
        op = change.get("op")
        if op == "add":
            keys = {"op", "path", "blob_sha", "mode"}
        elif op == "replace":
            keys = {"op", "path", "blob_sha", "mode", "expected_blob_sha"}
        else:
            raise PublishFailure("INVALID_SCHEMA", "bootstrap-v1 permits only add and replace")
        if set(change) != keys:
            raise PublishFailure("INVALID_SCHEMA", "change fields do not match the operation")
        if not isinstance(change.get("path"), str) or not (1 <= len(change["path"]) <= 300):
            raise PublishFailure("INVALID_SCHEMA", "change path is malformed")
        if change["path"] in seen_paths:
            raise PublishFailure("INVALID_SCHEMA", "a request may change each path only once")
        seen_paths.add(change["path"])
        if not _sha(change.get("blob_sha")):
            raise PublishFailure("INVALID_SCHEMA", "blob_sha must be an exact lowercase 40-hex SHA")
        if change.get("mode") not in REGULAR_MODES:
            raise PublishFailure("INVALID_SCHEMA", "only regular-file modes 100644 and 100755 are valid")
        if op == "replace" and not _sha(change.get("expected_blob_sha")):
            raise PublishFailure("INVALID_SCHEMA", "replace requires exact expected_blob_sha")
    ci = obj.get("ci")
    if not isinstance(ci, dict) or set(ci) != {"workflow"} or not isinstance(ci.get("workflow"), str):
        raise PublishFailure("INVALID_SCHEMA", "ci workflow declaration is malformed")
    return obj


def parse_transport_comment(body: Any) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(body, str):
        raise PublishFailure("INVALID_SCHEMA", "Issue comment body must be UTF-8 JSON text")
    try:
        obj = json.loads(body)
    except json.JSONDecodeError as exc:
        raise PublishFailure("INVALID_SCHEMA", "Issue comment must contain exactly one JSON envelope") from exc
    if isinstance(obj, dict) and obj.get("schema") == RESULT_SCHEMA:
        return "result", obj
    return "request", validate_request_shape(obj)


