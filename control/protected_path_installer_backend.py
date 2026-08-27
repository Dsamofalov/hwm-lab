#!/usr/bin/env python3
"""GitHub REST backend for inert protected-path installation."""
from __future__ import annotations

import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from protected_path_installer_contract import (
    ALLOWED_AUTHOR,
    ALLOWED_REPOSITORY,
    ARCHITECTURE_REPOSITORY,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    InstallFailure,
    canonical_json,
    is_sha,
    parse_transport_comment,
    request_fingerprint,
)


class ExpectedHeadChanged(Exception):
    """A non-force protected-path branch update lost its expected-head lease."""


class GitHubAPIBackend:
    """REST-only backend. No credential is placed in a Git remote, argv, or config."""

    def __init__(self, token: str, repository: str):
        if repository != ALLOWED_REPOSITORY:
            raise ValueError("backend repository is not bootstrap-v1 allowlisted")
        if not token:
            raise ValueError("protected-path installer token is required")
        self.token = token
        self.repository = repository
        self.owner, self.repo = repository.split("/", 1)
        self.arch_owner, self.arch_repo = ARCHITECTURE_REPOSITORY.split("/", 1)
        self.api = "https://api.github.com"
        self.api_version = "2026-03-10"

    def _request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[Any, dict[str, str], int]:
        data = None if payload is None else canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(
            self.api + path,
            method=method,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": self.api_version,
                "User-Agent": "hwm-protected-path-installer/bootstrap-v1",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                status = response.status
                headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            status = exc.code
            if status not in expected:
                raise RuntimeError(f"GitHub API returned HTTP {status}") from None
            raw = exc.read()
            headers = dict(exc.headers.items())
        except urllib.error.URLError as exc:
            raise RuntimeError("GitHub API unavailable") from exc
        if status not in expected:
            raise RuntimeError(f"GitHub API returned HTTP {status}")
        if not raw:
            return None, headers, status
        try:
            return json.loads(raw.decode("utf-8")), headers, status
        except Exception as exc:
            raise RuntimeError("GitHub API returned malformed JSON") from exc

    def _public_get(self, path: str) -> Any:
        """Read disclosure-safe public architecture state without cross-repository token authority."""
        request = urllib.request.Request(
            self.api + path,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": self.api_version,
                "User-Agent": "hwm-protected-path-installer/bootstrap-v1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"public GitHub API returned HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError("public GitHub API unavailable") from exc
        if status != 200:
            raise RuntimeError(f"public GitHub API returned HTTP {status}")
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise RuntimeError("public GitHub API returned malformed JSON") from exc

    def get_repository(self) -> dict[str, Any]:
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}")
        return data

    def get_architecture_issue(self, number: int) -> dict[str, Any]:
        data = self._public_get(f"/repos/{self.arch_owner}/{self.arch_repo}/issues/{number}")
        if not isinstance(data, dict):
            raise RuntimeError("public architecture Issue response was malformed")
        return data

    def get_issue_comment(self, comment_id: int) -> dict[str, Any]:
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/issues/comments/{comment_id}")
        return data

    def comment_belongs_to_issue(self, comment: dict[str, Any], issue_number: int) -> bool:
        issue_url = comment.get("issue_url") if isinstance(comment, dict) else None
        return isinstance(issue_url, str) and issue_url == f"{self.api}/repos/{self.owner}/{self.repo}/issues/{issue_number}"

    def branch_exists(self, branch: str) -> bool:
        ref = urllib.parse.quote(f"heads/{branch}", safe="/")
        _, _, status = self._request(
            "GET",
            f"/repos/{self.owner}/{self.repo}/git/ref/{ref}",
            expected=(200, 404),
        )
        return status == 200

    def get_branch_head(self, branch: str) -> str:
        ref = urllib.parse.quote(f"heads/{branch}", safe="/")
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/ref/{ref}")
        sha = ((data or {}).get("object") or {}).get("sha")
        if not is_sha(sha):
            raise RuntimeError("branch ref response omitted exact SHA")
        return sha

    def get_main_head(self) -> str:
        return self.get_branch_head("main")

    def get_commit(self, sha: str) -> dict[str, Any]:
        if not is_sha(sha):
            raise RuntimeError("commit lookup requires exact SHA")
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/commits/{sha}")
        return data

    def get_tree(self, tree_sha: str) -> list[dict[str, Any]]:
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}?recursive=1")
        if not isinstance(data, dict) or data.get("truncated"):
            raise RuntimeError("repository tree response was malformed or truncated")
        tree = data.get("tree")
        if not isinstance(tree, list):
            raise RuntimeError("repository tree response omitted entries")
        return tree

    def object_kind(self, sha: str) -> str | None:
        if not is_sha(sha):
            return None
        families = (("blobs", "blob"), ("trees", "tree"), ("commits", "commit"), ("tags", "tag"))
        for endpoint, kind in families:
            _, _, status = self._request(
                "GET",
                f"/repos/{self.owner}/{self.repo}/git/{endpoint}/{sha}",
                expected=(200, 404),
            )
            if status == 200:
                return kind
        return None

    def get_blob_bytes(self, sha: str) -> bytes:
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/blobs/{sha}")
        if not isinstance(data, dict) or data.get("sha") != sha or data.get("encoding") != "base64":
            raise RuntimeError("Git blob response is not exact base64 object data")
        content = data.get("content")
        if not isinstance(content, str):
            raise RuntimeError("Git blob response omitted content")
        try:
            raw = base64.b64decode(content, validate=False)
        except Exception as exc:
            raise RuntimeError("Git blob response contained invalid base64") from exc
        if isinstance(data.get("size"), int) and data["size"] != len(raw):
            raise RuntimeError("Git blob response size mismatch")
        actual = hashlib.sha1(f"blob {len(raw)}\0".encode("ascii") + raw).hexdigest()
        if actual != sha:
            raise RuntimeError("Git blob byte identity mismatch")
        return raw

    def create_candidate_commit(self, expected_head: str, changes: list[dict[str, Any]], message: str) -> str:
        self.get_commit(expected_head)
        base_commit = self.get_commit(expected_head)
        base_tree = ((base_commit or {}).get("tree") or {}).get("sha")
        if not is_sha(base_tree):
            raise RuntimeError("expected_head commit omitted base tree")
        entries = [
            {"path": item["path"], "mode": item["mode"], "type": "blob", "sha": item["blob_sha"]}
            for item in changes
        ]
        tree, _, _ = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/git/trees",
            {"base_tree": base_tree, "tree": entries},
            expected=(201,),
        )
        tree_sha = (tree or {}).get("sha")
        if not is_sha(tree_sha):
            raise RuntimeError("candidate tree construction omitted exact SHA")
        commit, _, _ = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/git/commits",
            {"message": message, "tree": tree_sha, "parents": [expected_head]},
            expected=(201,),
        )
        commit_sha = (commit or {}).get("sha")
        if not is_sha(commit_sha):
            raise RuntimeError("candidate commit construction omitted exact SHA")
        return commit_sha

    def compare_and_set_branch(self, branch: str, expected_head: str, new_head: str) -> None:
        if self.get_branch_head(branch) != expected_head:
            raise ExpectedHeadChanged()
        ref = urllib.parse.quote(f"heads/{branch}", safe="/")
        _, _, status = self._request(
            "PATCH",
            f"/repos/{self.owner}/{self.repo}/git/refs/{ref}",
            {"sha": new_head, "force": False},
            expected=(200, 422),
        )
        if status != 200:
            raise ExpectedHeadChanged()

    def dispatch_trusted_validation(
        self,
        *,
        workflow: str,
        carrier_issue: int,
        request_comment_id: int,
        request_id: str,
        request_fingerprint: str,
        candidate_commit_sha: str,
        protected_main_base_sha: str,
        required_check: str,
    ) -> dict[str, Any]:
        workflow_q = urllib.parse.quote(workflow, safe="")
        payload = {
            "ref": "main",
            "inputs": {
                "mode": "validate",
                "carrier_issue": str(carrier_issue),
                "request_comment_id": str(request_comment_id),
                "request_id": request_id,
                "request_fingerprint": request_fingerprint,
                "candidate_commit_sha": candidate_commit_sha,
                "protected_main_base_sha": protected_main_base_sha,
            },
            "return_run_details": True,
        }
        data, _, _ = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_q}/dispatches",
            payload,
            expected=(200,),
        )
        run_id = (data or {}).get("workflow_run_id")
        if not isinstance(run_id, int) or run_id < 1:
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation dispatch omitted workflow run id")
        run = self._wait_for_run(run_id)
        expected_path = f".github/workflows/{workflow}"
        if (
            run.get("event") != "workflow_dispatch"
            or run.get("path") != expected_path
            or run.get("head_sha") != protected_main_base_sha
            or run.get("conclusion") != "success"
        ):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation run is not successful on exact protected main source")
        jobs = self._get_run_jobs(run_id)
        matched = [job for job in jobs if job.get("name") == required_check]
        if len(matched) != 1 or matched[0].get("conclusion") != "success":
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "required trusted-static job did not succeed exactly once")
        return {
            "workflow": workflow,
            "required_check": required_check,
            "run_id": run_id,
            "head_sha": candidate_commit_sha,
            "source_ref": "refs/heads/main",
        }

    def _wait_for_run(self, run_id: int) -> dict[str, Any]:
        for _ in range(180):
            data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/actions/runs/{run_id}")
            if isinstance(data, dict) and data.get("status") == "completed":
                return data
            time.sleep(2)
        raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation workflow did not complete in bounded time", retryable=True)

    def _get_run_jobs(self, run_id: int) -> list[dict[str, Any]]:
        data, _, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/actions/runs/{run_id}/jobs?per_page=100")
        jobs = (data or {}).get("jobs") if isinstance(data, dict) else None
        if not isinstance(jobs, list):
            raise InstallFailure("TRUSTED_VALIDATION_FAILED", "trusted validation job listing was malformed")
        return jobs

    def _iter_repository_comments(self) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 51):
            data, _, _ = self._request(
                "GET",
                f"/repos/{self.owner}/{self.repo}/issues/comments?per_page=100&page={page}&sort=created&direction=asc",
            )
            if not isinstance(data, list):
                raise RuntimeError("issue comment listing malformed")
            comments.extend(data)
            if len(data) < 100:
                break
        return comments

    def find_results(self, request_id: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for comment in self._iter_repository_comments():
            user = comment.get("user") or {}
            if user.get("id") != RESULT_AUTHOR["github_account_id"] or user.get("login") != RESULT_AUTHOR["login"]:
                continue
            try:
                obj = json.loads(comment.get("body", ""))
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("schema") == RESULT_SCHEMA and obj.get("request_id") == request_id and obj.get("status") == "success":
                results.append(obj)
        return results

    def find_request_fingerprints(self, request_id: str) -> list[str]:
        out: list[str] = []
        for comment in self._iter_repository_comments():
            user = comment.get("user") or {}
            if (
                user.get("id") != ALLOWED_AUTHOR["github_account_id"]
                or user.get("login") != ALLOWED_AUTHOR["login"]
                or comment.get("author_association") != ALLOWED_AUTHOR["author_association"]
            ):
                continue
            try:
                kind, request = parse_transport_comment(comment.get("body", ""))
            except InstallFailure:
                continue
            if kind == "request" and request and request.get("request_id") == request_id:
                out.append(request_fingerprint(request))
        return out

    def post_result(self, issue_number: int, result: dict[str, Any]) -> None:
        self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/issues/{issue_number}/comments",
            {"body": canonical_json(result)},
            expected=(201,),
        )
