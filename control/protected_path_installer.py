#!/usr/bin/env python3
"""Controlled protected-path installer and trusted-static entry point."""
from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

from protected_path_installer_backend import ExpectedHeadChanged, GitHubAPIBackend
from protected_path_installer_contract import (
    ALLOWED_AUTHOR,
    ALLOWED_REPOSITORY,
    PROTECTED_SOURCE_REF,
    RESULT_SCHEMA,
    TRUSTED_CHECK,
    TRUSTED_WORKFLOW,
    InstallFailure,
    canonical_json,
    parse_transport_comment,
    request_fingerprint,
)
from protected_path_installer_policy import (
    error_result,
    issue_declared_runtime_paths,
    issue_installation_branch,
    issue_task_id,
    preflight_concurrency,
    validate_architecture_issue,
    validate_candidate_workflow,
    validate_protected_path,
)


def _event(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_output(values: dict[str, str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        for key, value in values.items():
            print(f"{key}={value}")
        return
    with open(output, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _author_is_owner(comment: Any) -> bool:
    if not isinstance(comment, dict):
        return False
    user = comment.get("user") or {}
    return (
        user.get("id") == ALLOWED_AUTHOR["github_account_id"]
        and user.get("login") == ALLOWED_AUTHOR["login"]
        and comment.get("author_association") == ALLOWED_AUTHOR["author_association"]
    )


def _tree_map(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {entry["path"]: entry for entry in entries if isinstance(entry, dict) and isinstance(entry.get("path"), str)}


def _leaf_map(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        entry["path"]: entry
        for entry in entries
        if isinstance(entry, dict)
        and isinstance(entry.get("path"), str)
        and entry.get("type") != "tree"
    }


class Installer:
    """Fail-closed protected-path publication engine.

    Candidate bytes are addressed only by Git object id. They are never checked out,
    imported, sourced, rendered as executable configuration, or executed here.
    """

    def __init__(self, backend: Any):
        self.backend = backend

    def handle_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        comment = event.get("comment") if isinstance(event, dict) else None
        issue_event = event.get("issue") if isinstance(event, dict) else None
        repo_event = event.get("repository") if isinstance(event, dict) else None
        raw_body = comment.get("body") if isinstance(comment, dict) else None
        raw_obj: Any = None
        if isinstance(raw_body, str):
            try:
                raw_obj = json.loads(raw_body)
            except json.JSONDecodeError:
                raw_obj = raw_body
        fingerprint = request_fingerprint(raw_obj)
        try:
            kind, request = parse_transport_comment(raw_body)
            if kind == "result":
                return None
        except InstallFailure as failure:
            return error_result(raw_obj, fingerprint, failure)

        assert request is not None
        fingerprint = request_fingerprint(request)
        try:
            if not _author_is_owner(comment):
                raise InstallFailure("UNAUTHORIZED_AUTHOR", "Issue comment actor and OWNER association are not exactly allowlisted")
            if not isinstance(issue_event, dict) or issue_event.get("pull_request"):
                raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "installer requests require a top-level hwm-lab carrier Issue")
            if not isinstance(repo_event, dict) or repo_event.get("full_name") != ALLOWED_REPOSITORY:
                raise InstallFailure("REPOSITORY_NOT_ALLOWED", "event repository is not the protected-path bootstrap repository")

            prior = self.backend.find_results(request["request_id"])
            if prior:
                fingerprints = {item.get("request_fingerprint") for item in prior}
                if fingerprints != {fingerprint}:
                    raise InstallFailure("REQUEST_ID_REUSE", "request_id was already used with different normalized content")
                result = copy.deepcopy(prior[0])
                result["idempotent_replay"] = True
                return result
            for existing in self.backend.find_request_fingerprints(request["request_id"]):
                if existing != fingerprint:
                    raise InstallFailure("REQUEST_ID_REUSE", "request_id appears in a different normalized owner request")

            carrier_issue = issue_event.get("number")
            comment_id = comment.get("id") if isinstance(comment, dict) else None
            if not isinstance(carrier_issue, int) or not isinstance(comment_id, int):
                raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "carrier Issue transport identity is incomplete")
            return self._install(request, fingerprint, carrier_issue, comment_id)
        except InstallFailure as failure:
            return error_result(request, fingerprint, failure)
        except Exception:
            return error_result(request, fingerprint, InstallFailure("INTERNAL_ERROR", "installer encountered a sanitized internal failure"))

    def _validate_live_request(self, request: dict[str, Any], *, require_expected_head: bool = True) -> tuple[str, dict[str, dict[str, Any]]]:
        if request["repository"] != ALLOWED_REPOSITORY:
            raise InstallFailure("REPOSITORY_NOT_ALLOWED", "bootstrap-v1 permits only Dsamofalov/hwm-lab")
        repo = self.backend.get_repository()
        default_branch = repo.get("default_branch")
        if request["installation_branch"] in {"main", default_branch}:
            raise InstallFailure("DEFAULT_BRANCH_FORBIDDEN", "protected-path installer cannot target the default branch")
        if request["protected_main_base_sha"] != self.backend.get_main_head():
            raise InstallFailure("PROTECTED_MAIN_BASE_MISMATCH", "protected main is not at protected_main_base_sha")

        architecture_issue = self.backend.get_architecture_issue(request["architecture_issue"])
        validate_architecture_issue(architecture_issue)
        if issue_task_id(architecture_issue.get("body")) != request["task_id"]:
            raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "architecture Issue task id does not match request")
        if issue_installation_branch(architecture_issue.get("body")) != request["installation_branch"]:
            raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "architecture Issue installation branch does not match request")
        declared = issue_declared_runtime_paths(architecture_issue.get("body"))
        if request["issue_declared_paths"] != declared:
            raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "request path declaration does not exactly match the architecture Issue runtime allowlist")

        validation = request["trusted_validation"]
        if (
            validation.get("workflow") != TRUSTED_WORKFLOW
            or validation.get("required_check") != TRUSTED_CHECK
            or validation.get("protected_source_ref") != PROTECTED_SOURCE_REF
        ):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation identity is not bootstrap-v1 allowlisted")
        if not self.backend.branch_exists(request["installation_branch"]):
            raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "declared installation branch does not exist")
        observed = self.backend.get_branch_head(request["installation_branch"])
        if require_expected_head and observed != request["expected_head"]:
            raise InstallFailure("EXPECTED_HEAD_MISMATCH", "installation branch is not at expected_head")

        base_commit = self.backend.get_commit(request["expected_head"])
        base_tree_sha = ((base_commit or {}).get("tree") or {}).get("sha")
        if not isinstance(base_tree_sha, str):
            raise InstallFailure("INTERNAL_ERROR", "expected_head commit omitted its tree")
        entries = _tree_map(self.backend.get_tree(base_tree_sha))

        for change in request["changes"]:
            path = change["path"]
            validate_protected_path(path, declared)
            current = entries.get(path)
            if change["op"] == "add":
                if current is not None:
                    raise InstallFailure("PATH_STATE_MISMATCH", "add target already exists at expected_head")
                prefix = ""
                for segment in path.split("/")[:-1]:
                    prefix = f"{prefix}/{segment}" if prefix else segment
                    ancestor = entries.get(prefix)
                    if ancestor is not None and ancestor.get("type") != "tree":
                        raise InstallFailure("PATH_STATE_MISMATCH", "add target has a non-directory ancestor")
            else:
                if current is None:
                    raise InstallFailure("PATH_STATE_MISMATCH", "replace target is absent at expected_head")
                if current.get("type") != "blob" or current.get("mode") not in {"100644", "100755"}:
                    raise InstallFailure("BLOB_NOT_REGULAR", "replace target is not a regular blob")
                if current.get("sha") != change["expected_blob_sha"]:
                    raise InstallFailure("PATH_STATE_MISMATCH", "replace target does not match expected_blob_sha")
            kind = self.backend.object_kind(change["blob_sha"])
            if kind is None:
                raise InstallFailure("BLOB_NOT_FOUND", "requested blob object does not exist")
            if kind != "blob":
                raise InstallFailure("BLOB_NOT_REGULAR", "requested object id does not identify a Git blob")
        return observed, entries

    def _inspect_candidate(self, request: dict[str, Any], candidate_commit_sha: str) -> None:
        commit = self.backend.get_commit(candidate_commit_sha)
        parents = commit.get("parents") if isinstance(commit, dict) else None
        if not isinstance(parents, list) or len(parents) != 1 or parents[0].get("sha") != request["expected_head"]:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate commit does not have exactly expected_head as its sole parent")
        candidate_tree_sha = ((commit.get("tree") or {}).get("sha"))
        base_tree_sha = (((self.backend.get_commit(request["expected_head"]) or {}).get("tree") or {}).get("sha"))
        if not isinstance(candidate_tree_sha, str) or not isinstance(base_tree_sha, str):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate or base commit omitted its tree")
        base = _leaf_map(self.backend.get_tree(base_tree_sha))
        candidate = _leaf_map(self.backend.get_tree(candidate_tree_sha))
        changed_paths = sorted(path for path in set(base) | set(candidate) if base.get(path) != candidate.get(path))
        expected_paths = sorted(change["path"] for change in request["changes"])
        if changed_paths != expected_paths:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate tree changes do not exactly match the request")
        for change in request["changes"]:
            entry = candidate.get(change["path"])
            if (
                not isinstance(entry, dict)
                or entry.get("type") != "blob"
                or entry.get("mode") != change["mode"]
                or entry.get("sha") != change["blob_sha"]
            ):
                raise InstallFailure("TRUSTED_VALIDATION_FAILED", "candidate path/mode/blob inventory does not match the request")

    def _install(self, request: dict[str, Any], fingerprint: str, carrier_issue: int, request_comment_id: int) -> dict[str, Any]:
        observed, _ = self._validate_live_request(request)
        try:
            candidate = self.backend.create_candidate_commit(
                expected_head=request["expected_head"],
                changes=request["changes"],
                message=request["commit_message"],
            )
        except ExpectedHeadChanged as exc:
            raise InstallFailure("EXPECTED_HEAD_MISMATCH", "installation branch changed before inert candidate construction") from exc
        self._inspect_candidate(request, candidate)

        validation = self.backend.dispatch_trusted_validation(
            workflow=TRUSTED_WORKFLOW,
            carrier_issue=carrier_issue,
            request_comment_id=request_comment_id,
            request_id=request["request_id"],
            request_fingerprint=fingerprint,
            candidate_commit_sha=candidate,
            protected_main_base_sha=request["protected_main_base_sha"],
            required_check=TRUSTED_CHECK,
        )
        if self.backend.get_main_head() != request["protected_main_base_sha"]:
            raise InstallFailure("PROTECTED_MAIN_BASE_MISMATCH", "protected main changed after trusted validation")
        if self.backend.get_branch_head(request["installation_branch"]) != request["expected_head"]:
            raise InstallFailure("EXPECTED_HEAD_MISMATCH", "installation branch changed after trusted validation")
        try:
            self.backend.compare_and_set_branch(request["installation_branch"], request["expected_head"], candidate)
        except ExpectedHeadChanged as exc:
            raise InstallFailure("EXPECTED_HEAD_MISMATCH", "non-force installation branch update lost its expected-head lease") from exc
        if self.backend.get_branch_head(request["installation_branch"]) != candidate:
            raise InstallFailure("EXPECTED_HEAD_MISMATCH", "installation branch did not read back at candidate head")
        return {
            "schema": RESULT_SCHEMA,
            "request_id": request["request_id"],
            "status": "success",
            "repository": request["repository"],
            "architecture_issue": request["architecture_issue"],
            "task_id": request["task_id"],
            "installation_branch": request["installation_branch"],
            "expected_head": request["expected_head"],
            "protected_main_base_sha": request["protected_main_base_sha"],
            "observed_head_before": observed,
            "new_head": candidate,
            "commit_sha": candidate,
            "changes": copy.deepcopy(request["changes"]),
            "trusted_validation": validation,
            "request_fingerprint": fingerprint,
            "idempotent_replay": False,
        }

    def trusted_validate(self, event: dict[str, Any], executing_sha: str) -> None:
        if not isinstance(event, dict) or event.get("repository", {}).get("full_name") != ALLOWED_REPOSITORY:
            raise InstallFailure("REPOSITORY_NOT_ALLOWED", "trusted validation event repository is not allowlisted")
        inputs = event.get("inputs")
        if not isinstance(inputs, dict) or inputs.get("mode") != "validate":
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation dispatch inputs are malformed")
        required = {
            "carrier_issue",
            "request_comment_id",
            "request_id",
            "request_fingerprint",
            "candidate_commit_sha",
            "protected_main_base_sha",
        }
        if not required.issubset(inputs):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation dispatch omitted required bindings")
        try:
            carrier_issue = int(inputs["carrier_issue"])
            comment_id = int(inputs["request_comment_id"])
        except (TypeError, ValueError) as exc:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation carrier identity is malformed") from exc
        if executing_sha != inputs["protected_main_base_sha"]:
            raise InstallFailure("PROTECTED_MAIN_BASE_MISMATCH", "trusted validation source SHA is not protected_main_base_sha")
        comment = self.backend.get_issue_comment(comment_id)
        if not _author_is_owner(comment):
            raise InstallFailure("UNAUTHORIZED_AUTHOR", "trusted validation request comment actor is not exactly allowlisted")
        if not self.backend.comment_belongs_to_issue(comment, carrier_issue):
            raise InstallFailure("ISSUE_TASK_BRANCH_MISMATCH", "trusted validation comment does not belong to the declared carrier Issue")
        kind, request = parse_transport_comment(comment.get("body"))
        if kind != "request" or request is None:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation comment is not an installer request")
        fingerprint = request_fingerprint(request)
        if inputs["request_id"] != request["request_id"] or inputs["request_fingerprint"] != fingerprint:
            raise InstallFailure("REQUEST_ID_REUSE", "trusted validation request identity or fingerprint changed")
        if inputs["protected_main_base_sha"] != request["protected_main_base_sha"]:
            raise InstallFailure("PROTECTED_MAIN_BASE_MISMATCH", "trusted validation protected-main binding changed")
        candidate = inputs["candidate_commit_sha"]
        self._validate_live_request(request)
        self._inspect_candidate(request, candidate)
        for change in request["changes"]:
            if change["path"].lower().startswith(".github/workflows/"):
                raw = self.backend.get_blob_bytes(change["blob_sha"])
                validate_candidate_workflow(change["path"], raw)


def _runtime_backend(event: dict[str, Any]) -> GitHubAPIBackend:
    token = os.environ.pop("HWM_PROTECTED_PATH_INSTALLER_TOKEN", None)
    if not token:
        raise RuntimeError("protected-path installer job token is unavailable")
    repository = ((event.get("repository") or {}).get("full_name"))
    if repository != ALLOWED_REPOSITORY:
        raise RuntimeError("event repository is not bootstrap-v1 allowlisted")
    return GitHubAPIBackend(token=token, repository=repository)


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"preflight", "install", "validate"}:
        print("usage: protected_path_installer.py {preflight|install|validate} EVENT_JSON", file=sys.stderr)
        return 2
    event = _event(argv[2])
    if argv[1] == "preflight":
        _write_output(preflight_concurrency(event))
        return 0
    try:
        backend = _runtime_backend(event)
        installer = Installer(backend)
        if argv[1] == "validate":
            installer.trusted_validate(event, os.environ.get("GITHUB_SHA", ""))
            print("trusted_static_status=success")
            return 0
        result = installer.handle_event(event)
        if result is None:
            return 0
        issue_number = (event.get("issue") or {}).get("number")
        if not isinstance(issue_number, int):
            raise RuntimeError("event does not identify a carrier Issue")
        backend.post_result(issue_number, result)
        print(f"install_status={result['status']} request_id={result['request_id']}")
        return 0
    except InstallFailure as failure:
        print(f"protected-path installer rejected request: {failure.code}", file=sys.stderr)
        return 1
    except Exception:
        print("protected-path installer failed with sanitized internal error", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))


__all__ = [
    "ALLOWED_AUTHOR",
    "GitHubAPIBackend",
    "Installer",
    "InstallFailure",
    "canonical_json",
    "preflight_concurrency",
    "request_fingerprint",
]
