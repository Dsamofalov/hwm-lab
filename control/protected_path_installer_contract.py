#!/usr/bin/env python3
"""bootstrap-v1 protected-path installer transport contract."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

REQUEST_SCHEMA = "hwm-protected-path-install-request/bootstrap-v1"
RESULT_SCHEMA = "hwm-protected-path-install-result/bootstrap-v1"
ALLOWED_REPOSITORY = "Dsamofalov/hwm-lab"
ARCHITECTURE_REPOSITORY = "Dsamofalov/hwm-control"
ALLOWED_AUTHOR = {
    "github_account_id": 25666939,
    "login": "Dsamofalov",
    "author_association": "OWNER",
}
RESULT_AUTHOR = {"github_account_id": 41898282, "login": "github-actions[bot]"}
TRUSTED_WORKFLOW = "protected-path-installer.yml"
TRUSTED_CHECK = "protected-path-installer/trusted-static"
PROTECTED_SOURCE_REF = "refs/heads/main"
REGULAR_MODES = {"100644", "100755"}
ERROR_CODES = {
    "INVALID_SCHEMA",
    "UNAUTHORIZED_AUTHOR",
    "REPOSITORY_NOT_ALLOWED",
    "ARCHITECTURE_ISSUE_NOT_CLAIMED",
    "REQUIRED_LABEL_MISSING",
    "ISSUE_TASK_BRANCH_MISMATCH",
    "EXPECTED_HEAD_MISMATCH",
    "PROTECTED_MAIN_BASE_MISMATCH",
    "DEFAULT_BRANCH_FORBIDDEN",
    "UNDECLARED_PATH",
    "PATH_CLASS_FORBIDDEN",
    "SELF_MODIFICATION_FORBIDDEN",
    "ORDINARY_PUBLISHER_MODIFICATION_FORBIDDEN",
    "BOOTSTRAP_WORKFLOW_MODIFICATION_FORBIDDEN",
    "CODEOWNERS_FORBIDDEN",
    "RULESET_OR_SETTINGS_FORBIDDEN",
    "SECRET_OR_ENVIRONMENT_PATH_FORBIDDEN",
    "PATH_STATE_MISMATCH",
    "BLOB_NOT_FOUND",
    "BLOB_NOT_REGULAR",
    "REQUEST_ID_REUSE",
    "TRUSTED_VALIDATION_FAILED",
    "INTERNAL_ERROR",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQ_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TASK_ID_RE = re.compile(r"^I[0-9]{2}-[0-9]{4}$")
BRANCH_RE = re.compile(r"^agent/infra-[0-9]{4}-[A-Za-z0-9._-]+$")


class InstallFailure(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        if code not in ERROR_CODES:
            code = "INTERNAL_ERROR"
            message = "installer rejected an unclassified failure"
            retryable = False
        super().__init__(message)
        self.code = code
        self.message = sanitize_message(message)
        self.retryable = bool(retryable)


def sanitize_message(message: Any) -> str:
    text = " ".join(str(message).replace("\r", " ").replace("\n", " ").split())
    lowered = text.lower()
    for sensitive in (
        "authorization:",
        "bearer ",
        "token=",
        "github_token",
        "private key",
        "cookie:",
        "set-cookie:",
    ):
        if sensitive in lowered:
            return "sanitized installer diagnostic"
    return text[:240] or "installer failure"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def request_fingerprint(value: Any) -> str:
    try:
        raw = canonical_json(value).encode("utf-8")
    except Exception:
        raw = repr(value).encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()


def is_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _plain_string(value: Any, *, min_len: int = 1, max_len: int = 300) -> bool:
    return (
        isinstance(value, str)
        and min_len <= len(value) <= max_len
        and value.strip() == value
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    )


def validate_request_shape(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise InstallFailure("INVALID_SCHEMA", "request envelope must be one JSON object")
    top = {
        "schema",
        "request_id",
        "repository",
        "architecture_issue",
        "task_id",
        "installation_branch",
        "expected_head",
        "protected_main_base_sha",
        "issue_declared_paths",
        "changes",
        "commit_message",
        "trusted_validation",
    }
    if set(obj) != top or obj.get("schema") != REQUEST_SCHEMA:
        raise InstallFailure("INVALID_SCHEMA", "request fields or schema do not match bootstrap-v1")
    if not isinstance(obj.get("request_id"), str) or REQ_ID_RE.fullmatch(obj["request_id"]) is None:
        raise InstallFailure("INVALID_SCHEMA", "request_id is invalid")
    if not isinstance(obj.get("repository"), str) or REPO_RE.fullmatch(obj["repository"]) is None:
        raise InstallFailure("INVALID_SCHEMA", "repository identity is malformed")
    issue = obj.get("architecture_issue")
    if not isinstance(issue, int) or isinstance(issue, bool) or issue < 1:
        raise InstallFailure("INVALID_SCHEMA", "architecture_issue must be a positive integer")
    if not isinstance(obj.get("task_id"), str) or TASK_ID_RE.fullmatch(obj["task_id"]) is None:
        raise InstallFailure("INVALID_SCHEMA", "task_id is malformed")
    if not isinstance(obj.get("installation_branch"), str) or BRANCH_RE.fullmatch(obj["installation_branch"]) is None:
        raise InstallFailure("INVALID_SCHEMA", "installation_branch is malformed")
    if not is_sha(obj.get("expected_head")) or not is_sha(obj.get("protected_main_base_sha")):
        raise InstallFailure("INVALID_SCHEMA", "expected_head and protected_main_base_sha must be exact lowercase 40-hex SHAs")
    declared = obj.get("issue_declared_paths")
    if not isinstance(declared, list) or not (1 <= len(declared) <= 32):
        raise InstallFailure("INVALID_SCHEMA", "issue_declared_paths must contain one to 32 paths")
    if any(not _plain_string(item) for item in declared) or len(set(declared)) != len(declared):
        raise InstallFailure("INVALID_SCHEMA", "issue_declared_paths must contain unique path strings")
    changes = obj.get("changes")
    if not isinstance(changes, list) or not (1 <= len(changes) <= 32):
        raise InstallFailure("INVALID_SCHEMA", "changes must contain one to 32 operations")
    seen: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            raise InstallFailure("INVALID_SCHEMA", "each change must be an object")
        op = change.get("op")
        expected_keys = (
            {"op", "path", "blob_sha", "mode"}
            if op == "add"
            else {"op", "path", "blob_sha", "mode", "expected_blob_sha"}
            if op == "replace"
            else None
        )
        if expected_keys is None or set(change) != expected_keys:
            raise InstallFailure("INVALID_SCHEMA", "change fields do not match add/replace")
        path = change.get("path")
        if not _plain_string(path) or path in seen:
            raise InstallFailure("INVALID_SCHEMA", "each change path must be unique and well formed")
        seen.add(path)
        if not is_sha(change.get("blob_sha")):
            raise InstallFailure("INVALID_SCHEMA", "blob_sha must be an exact lowercase 40-hex SHA")
        if change.get("mode") not in REGULAR_MODES:
            raise InstallFailure("INVALID_SCHEMA", "only regular-file modes 100644 and 100755 are valid")
        if op == "replace" and not is_sha(change.get("expected_blob_sha")):
            raise InstallFailure("INVALID_SCHEMA", "replace requires exact expected_blob_sha")
    message = obj.get("commit_message")
    if not _plain_string(message, max_len=240) or "\n" in message or "\r" in message:
        raise InstallFailure("INVALID_SCHEMA", "commit_message must be one non-empty line")
    validation = obj.get("trusted_validation")
    if (
        not isinstance(validation, dict)
        or set(validation) != {"workflow", "required_check", "protected_source_ref"}
        or not _plain_string(validation.get("workflow"), max_len=128)
        or not _plain_string(validation.get("required_check"), max_len=128)
        or validation.get("protected_source_ref") != PROTECTED_SOURCE_REF
    ):
        raise InstallFailure("INVALID_SCHEMA", "trusted_validation declaration is malformed")
    return obj


def parse_transport_comment(body: Any) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(body, str):
        raise InstallFailure("INVALID_SCHEMA", "Issue comment body must be UTF-8 JSON text")
    try:
        obj = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InstallFailure("INVALID_SCHEMA", "Issue comment must contain exactly one JSON envelope") from exc
    if isinstance(obj, dict) and obj.get("schema") == RESULT_SCHEMA:
        return "result", obj
    return "request", validate_request_shape(obj)
