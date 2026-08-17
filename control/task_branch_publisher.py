#!/usr/bin/env python3
"""Controlled hwm-control task-branch publisher for bootstrap-v1.

The privileged path operates on Git metadata/objects only. Candidate branch content is
never checked out, imported, evaluated, or executed in the publisher process.
"""
from __future__ import annotations

import copy
import json
from typing import Any

from publisher_contract import (
    ALLOWED_AUTHOR,
    ALLOWED_REPOSITORY,
    ALLOWED_WORKFLOW,
    INFRA_BRANCH_RE,
    REGULAR_MODES,
    RESULT_SCHEMA,
    PublishFailure,
    canonical_json,
    parse_transport_comment,
    request_fingerprint,
)
from publisher_policy import (
    _branch_lock,
    _load_manifest,
    error_result,
    path_forbidden,
    preflight_concurrency,
    recorded_issue_branches,
)
from publisher_backend import ExpectedHeadChanged, GitHubAPIBackend

class Publisher:
    def __init__(self, backend: Any, manifest: dict[str, Any] | None = None):
        self.backend = backend
        self.manifest = manifest or _load_manifest()

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
        except PublishFailure as failure:
            return error_result(raw_obj, fingerprint, failure)

        assert request is not None
        fingerprint = request_fingerprint(request)
        author = comment.get("user") if isinstance(comment, dict) else None
        if not isinstance(author, dict) or author.get("id") != ALLOWED_AUTHOR["github_account_id"] or author.get("login") != ALLOWED_AUTHOR["login"]:
            return error_result(request, fingerprint, PublishFailure("UNAUTHORIZED_AUTHOR", "Issue comment author is not exactly allowlisted"))
        if not isinstance(issue_event, dict) or issue_event.get("pull_request"):
            return error_result(request, fingerprint, PublishFailure("BRANCH_TASK_MISMATCH", "publish requests must be top-level task Issue comments"))
        if issue_event.get("number") != request["task_issue"]:
            return error_result(request, fingerprint, PublishFailure("BRANCH_TASK_MISMATCH", "request comment is not on the declared task Issue"))
        if not isinstance(repo_event, dict) or repo_event.get("full_name") != request["repository"]:
            return error_result(request, fingerprint, PublishFailure("BRANCH_TASK_MISMATCH", "event repository does not match the request repository"))

        prior = self.backend.find_results(request["request_id"])
        if prior:
            fingerprints = {item.get("request_fingerprint") for item in prior}
            if fingerprints != {fingerprint}:
                return error_result(request, fingerprint, PublishFailure("REQUEST_ID_REUSE", "request_id was already used with different normalized content"))
            original = copy.deepcopy(prior[0])
            original["idempotent_replay"] = True
            return original
        for existing_fingerprint in self.backend.find_request_fingerprints(request["request_id"]):
            if existing_fingerprint != fingerprint:
                return error_result(request, fingerprint, PublishFailure("REQUEST_ID_REUSE", "request_id appears in a different normalized request"))

        key = (request["repository"], request["task_branch"])
        with _branch_lock(key):
            prior = self.backend.find_results(request["request_id"])
            if prior:
                fingerprints = {item.get("request_fingerprint") for item in prior}
                if fingerprints != {fingerprint}:
                    return error_result(request, fingerprint, PublishFailure("REQUEST_ID_REUSE", "request_id was already used with different normalized content"))
                original = copy.deepcopy(prior[0])
                original["idempotent_replay"] = True
                return original
            return self._publish(request, fingerprint)

    def _publish(self, request: dict[str, Any], fingerprint: str) -> dict[str, Any]:
        observed: str | None = None
        try:
            if request["repository"] != ALLOWED_REPOSITORY:
                raise PublishFailure("REPOSITORY_NOT_ALLOWED", "bootstrap-v1 initially permits only Dsamofalov/hwm-control")
            repo = self.backend.get_repository()
            default_branch = repo.get("default_branch")
            if request["task_branch"] in {"main", default_branch}:
                raise PublishFailure("FORBIDDEN_TARGET", "publisher cannot target main or the repository default branch")
            match = INFRA_BRANCH_RE.fullmatch(request["task_branch"])
            if match is None or int(match.group(1)) != request["task_issue"]:
                raise PublishFailure("BRANCH_TASK_MISMATCH", "task branch does not match the hwm-control task Issue number")
            issue = self.backend.get_issue(request["task_issue"])
            labels = {item.get("name") if isinstance(item, dict) else item for item in issue.get("labels", [])}
            if issue.get("state") != "open" or "claimed" not in labels:
                raise PublishFailure("TASK_NOT_CLAIMED", "task Issue must be open and claimed")
            recorded = recorded_issue_branches(issue.get("body"))
            if recorded and recorded != {request["task_branch"]}:
                raise PublishFailure("BRANCH_TASK_MISMATCH", "Issue-recorded branch identity does not match request")
            if not self.backend.branch_exists(request["task_branch"]):
                raise PublishFailure("BRANCH_TASK_MISMATCH", "declared task branch does not exist")
            if self.backend.branch_is_protected(request["task_branch"]):
                raise PublishFailure("FORBIDDEN_TARGET", "protected integration branches are not publisher targets")
            observed = self.backend.get_branch_head(request["task_branch"])
            if observed != request["expected_head"]:
                raise PublishFailure("EXPECTED_HEAD_MISMATCH", "remote task branch is not at expected_head")
            if request["ci"]["workflow"] != ALLOWED_WORKFLOW:
                raise PublishFailure("FORBIDDEN_TARGET", "requested CI workflow is not allowlisted")

            for change in request["changes"]:
                if path_forbidden(change["path"], self.manifest):
                    raise PublishFailure("FORBIDDEN_PATH", "requested path is forbidden by protected publisher policy")

            commit = self.backend.get_commit(request["expected_head"])
            base_tree_sha = commit["tree"]["sha"]
            entries = self.backend.get_tree(base_tree_sha)
            by_path = {entry["path"]: entry for entry in entries}
            for change in request["changes"]:
                path = change["path"]
                current = by_path.get(path)
                if change["op"] == "add":
                    if current is not None:
                        raise PublishFailure("PATH_STATE_MISMATCH", "add target already exists at expected_head")
                    prefix = ""
                    for segment in path.split("/")[:-1]:
                        prefix = f"{prefix}/{segment}" if prefix else segment
                        ancestor = by_path.get(prefix)
                        if ancestor is not None and ancestor.get("type") != "tree":
                            raise PublishFailure("PATH_STATE_MISMATCH", "add target has a non-directory ancestor")
                else:
                    if current is None:
                        raise PublishFailure("PATH_STATE_MISMATCH", "replace target is absent at expected_head")
                    if current.get("type") != "blob" or current.get("mode") not in REGULAR_MODES:
                        raise PublishFailure("BLOB_NOT_REGULAR", "replace target is not a regular blob")
                    if current.get("sha") != change["expected_blob_sha"]:
                        raise PublishFailure("PATH_STATE_MISMATCH", "replace target does not match expected_blob_sha")
                kind = self.backend.object_kind(change["blob_sha"])
                if kind is None:
                    raise PublishFailure("BLOB_NOT_FOUND", "requested blob object does not exist")
                if kind != "blob":
                    raise PublishFailure("BLOB_NOT_REGULAR", "requested object id does not identify a Git blob")

            try:
                new_head = self.backend.create_candidate_commit(
                    branch=request["task_branch"],
                    expected_head=request["expected_head"],
                    changes=request["changes"],
                    message=(
                        f"publisher: {request['request_id']}\n\n"
                        f"HWM-Publish-Request-Id: {request['request_id']}\n"
                        f"HWM-Publish-Fingerprint: {fingerprint}"
                    ),
                )
            except ExpectedHeadChanged as exc:
                raise PublishFailure("EXPECTED_HEAD_MISMATCH", "remote task branch changed before candidate commit construction") from exc
            parent = self.backend.local_commit_parent(new_head)
            if parent != request["expected_head"]:
                raise PublishFailure("INTERNAL_ERROR", "candidate commit parent does not equal expected_head")

            if not self.backend.compare_and_set_branch(request["task_branch"], request["expected_head"], new_head):
                now = self.backend.get_branch_head(request["task_branch"])
                if now != request["expected_head"]:
                    raise PublishFailure("EXPECTED_HEAD_MISMATCH", "atomic branch lease failed because remote head changed")
                raise PublishFailure("INTERNAL_ERROR", "atomic branch lease failed without a competing ref move")
            if self.backend.get_branch_head(request["task_branch"]) != new_head:
                raise PublishFailure("EXPECTED_HEAD_MISMATCH", "task branch moved after publication CAS")

            try:
                dispatch = self.backend.dispatch_ci(
                    workflow=ALLOWED_WORKFLOW,
                    branch=request["task_branch"],
                    request_id=request["request_id"],
                    new_head=new_head,
                )
                run_id = dispatch.get("run_id")
                if not isinstance(run_id, int) or run_id < 1:
                    raise RuntimeError("dispatch response omitted workflow run id")
                run = self.backend.get_workflow_run(run_id)
                expected_path = f".github/workflows/{ALLOWED_WORKFLOW}"
                if run.get("head_sha") != new_head or run.get("event") != "workflow_dispatch" or run.get("path") != expected_path:
                    raise RuntimeError("workflow run identity does not prove exact dispatched head")
            except Exception as exc:
                raise PublishFailure("CI_DISPATCH_FAILED", "explicit ordinary-CI dispatch could not be associated with exact new_head") from exc

            return {
                "schema": RESULT_SCHEMA,
                "request_id": request["request_id"],
                "status": "success",
                "repository": request["repository"],
                "task_issue": request["task_issue"],
                "task_branch": request["task_branch"],
                "expected_head": request["expected_head"],
                "observed_head_before": observed,
                "new_head": new_head,
                "commit_sha": new_head,
                "changes": copy.deepcopy(request["changes"]),
                "request_fingerprint": fingerprint,
                "idempotent_replay": False,
                "ci_dispatch": {"workflow": ALLOWED_WORKFLOW, "run_id": run_id, "head_sha": new_head},
            }
        except PublishFailure as failure:
            return error_result(request, fingerprint, failure, observed_head=observed)
        except Exception:
            return error_result(request, fingerprint, PublishFailure("INTERNAL_ERROR", "publisher encountered a sanitized internal failure"), observed_head=observed)



__all__ = [
    "ALLOWED_AUTHOR",
    "GitHubAPIBackend",
    "Publisher",
    "PublishFailure",
    "canonical_json",
    "path_forbidden",
    "preflight_concurrency",
    "request_fingerprint",
]
