#!/usr/bin/env python3
"""GitHub/bootstrap backend: inert Git objects, HTTPS lease update, exact CI dispatch."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import json
import os
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator

from publisher_contract import (
    ALLOWED_AUTHOR,
    ALLOWED_REPOSITORY,
    PUBLISHER_RESULT_AUTHOR,
    RESULT_SCHEMA,
    PublishFailure,
    _sha,
    canonical_json,
    parse_transport_comment,
    request_fingerprint,
)

GIT_REMOTE = "https://github.com/Dsamofalov/hwm-lab.git"
PUBLIC_GIT_REMOTE = GIT_REMOTE


class ExpectedHeadChanged(Exception):
    """Trusted backend observed that the remote branch no longer equals expected_head."""


class GitHubAPIBackend:
    """GitHub implementation. Candidate contents are inert Git blob data, never checkout input."""

    def __init__(
        self,
        token: str,
        repository: str,
        repo_root: Path | None = None,
    ):
        if repository != ALLOWED_REPOSITORY:
            raise ValueError("backend repository is not bootstrap-v1 allowlisted")
        if not token:
            raise ValueError("publisher token is required")
        self.token = token
        self.repository = repository
        self.owner, self.repo = repository.split("/", 1)
        self.repo_root = repo_root or Path.cwd()
        self.api = "https://api.github.com"
        self.api_version = "2026-03-10"

    def _request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        expected: tuple[int, ...] = (200,),
    ) -> tuple[Any, dict[str, str]]:
        data = None if payload is None else canonical_json(payload).encode("utf-8")
        req = urllib.request.Request(
            self.api + path,
            method=method,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": self.api_version,
                "User-Agent": "hwm-control-publisher/bootstrap-v1",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
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
            return None, headers
        try:
            return json.loads(raw.decode("utf-8")), headers
        except Exception as exc:
            raise RuntimeError("GitHub API returned malformed JSON") from exc

    def get_repository(self) -> dict[str, Any]:
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}")
        return data

    def get_issue(self, number: int) -> dict[str, Any]:
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/issues/{number}")
        return data

    def branch_exists(self, branch: str) -> bool:
        branch_q = urllib.parse.quote(branch, safe="")
        try:
            self._request("GET", f"/repos/{self.owner}/{self.repo}/branches/{branch_q}")
            return True
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return False
            raise

    def branch_is_protected(self, branch: str) -> bool:
        branch_q = urllib.parse.quote(branch, safe="")
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/branches/{branch_q}")
        return bool((data or {}).get("protected"))

    def get_branch_head(self, branch: str) -> str:
        ref = urllib.parse.quote(f"heads/{branch}", safe="/")
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/ref/{ref}")
        sha = ((data or {}).get("object") or {}).get("sha")
        if not _sha(sha):
            raise RuntimeError("branch ref response missing exact SHA")
        return sha

    def get_commit(self, sha: str) -> dict[str, Any]:
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/commits/{sha}")
        return data

    def get_tree(self, tree_sha: str) -> list[dict[str, Any]]:
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}?recursive=1")
        if data.get("truncated"):
            raise RuntimeError("repository tree response was truncated")
        return data.get("tree", [])

    def _exists(self, path: str) -> bool:
        try:
            self._request("GET", path)
            return True
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                return False
            raise

    def object_kind(self, sha: str) -> str | None:
        if self._exists(f"/repos/{self.owner}/{self.repo}/git/blobs/{sha}"):
            return "blob"
        if self._exists(f"/repos/{self.owner}/{self.repo}/git/trees/{sha}"):
            return "tree"
        if self._exists(f"/repos/{self.owner}/{self.repo}/git/commits/{sha}"):
            return "commit"
        if self._exists(f"/repos/{self.owner}/{self.repo}/git/tags/{sha}"):
            return "tag"
        return None

    def _run_git(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> bytes:
        proc = subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError("trusted Git metadata operation failed")
        return proc.stdout

    def _fetch_exact_branch(self, branch: str, expected_head: str) -> None:
        # Public fetch transfers Git objects only. No checkout/reset/switch touches candidate content.
        self._run_git(["fetch", "--no-tags", "--quiet", PUBLIC_GIT_REMOTE, f"refs/heads/{branch}"])
        fetched = self._run_git(["rev-parse", "FETCH_HEAD"]).decode("ascii").strip()
        if fetched != expected_head:
            raise ExpectedHeadChanged()

    def _blob_bytes(self, sha: str) -> bytes:
        data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/git/blobs/{sha}")
        if not isinstance(data, dict) or data.get("sha") != sha or data.get("encoding") != "base64":
            raise RuntimeError("Git blob response is not exact base64 object data")
        content = data.get("content")
        if not isinstance(content, str):
            raise RuntimeError("Git blob response omitted content")
        try:
            raw = base64.b64decode(content, validate=False)
        except Exception as exc:
            raise RuntimeError("Git blob response contained invalid base64") from exc
        declared = data.get("size")
        if isinstance(declared, int) and declared != len(raw):
            raise RuntimeError("Git blob response size mismatch")
        return raw

    def _materialize_blob(self, sha: str) -> None:
        # Candidate bytes enter only git hash-object stdin; they are never written into the worktree or executed.
        raw = self._blob_bytes(sha)
        actual = self._run_git(["hash-object", "-w", "--stdin"], input_bytes=raw).decode("ascii").strip()
        if actual != sha:
            raise RuntimeError("candidate blob hash verification failed")

    def create_candidate_commit(
        self,
        branch: str,
        expected_head: str,
        changes: list[dict[str, Any]],
        message: str,
    ) -> str:
        self._fetch_exact_branch(branch, expected_head)
        for change in changes:
            self._materialize_blob(change["blob_sha"])
        with tempfile.TemporaryDirectory(prefix="hwm-publisher-index-") as tmp:
            env = os.environ.copy()
            env.update({
                "GIT_INDEX_FILE": str(Path(tmp) / "index"),
                "GIT_AUTHOR_NAME": "hwm-control publisher",
                "GIT_AUTHOR_EMAIL": "github-actions[bot]@users.noreply.github.com",
                "GIT_COMMITTER_NAME": "hwm-control publisher",
                "GIT_COMMITTER_EMAIL": "github-actions[bot]@users.noreply.github.com",
            })
            self._run_git(["read-tree", expected_head], env=env)
            for change in changes:
                self._run_git(
                    [
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        f"{change['mode']},{change['blob_sha']},{change['path']}",
                    ],
                    env=env,
                )
            tree_sha = self._run_git(["write-tree"], env=env).decode("ascii").strip()
            if not _sha(tree_sha):
                raise RuntimeError("candidate tree construction omitted SHA")
            commit_sha = self._run_git(
                ["commit-tree", tree_sha, "-p", expected_head, "-m", message],
                env=env,
            ).decode("ascii").strip()
            if not _sha(commit_sha):
                raise RuntimeError("candidate commit construction omitted SHA")
            return commit_sha

    def local_commit_parent(self, commit_sha: str) -> str | None:
        raw = self._run_git(["cat-file", "-p", commit_sha]).decode("utf-8", "replace")
        parents = [line.split(" ", 1)[1] for line in raw.splitlines() if line.startswith("parent ")]
        if len(parents) != 1 or not _sha(parents[0]):
            return None
        return parents[0]

    @contextmanager
    def _https_git_auth(self) -> Iterator[dict[str, str]]:
        """Yield a Git environment that exposes only paths, never the token itself, to git/ps/config."""
        with tempfile.TemporaryDirectory(prefix="hwm-publisher-askpass-") as tmp:
            root = Path(tmp)
            token_path = root / "token"
            askpass_path = root / "askpass.py"
            token_path.write_text(self.token, encoding="utf-8")
            token_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            askpass_path.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "prompt = sys.argv[1] if len(sys.argv) > 1 else ''\n"
                "if 'Username' in prompt:\n"
                "    sys.stdout.write('x-access-token')\n"
                "elif 'Password' in prompt:\n"
                "    path = os.environ.get('HWM_PUBLISHER_ASKPASS_TOKEN_FILE')\n"
                "    if not path:\n"
                "        raise SystemExit(2)\n"
                "    with open(path, 'r', encoding='utf-8') as handle:\n"
                "        sys.stdout.write(handle.read())\n"
                "else:\n"
                "    raise SystemExit(2)\n",
                encoding="utf-8",
            )
            askpass_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            env = os.environ.copy()
            for name in ("HWM_PUBLISHER_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
                env.pop(name, None)
            env.update({
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": str(askpass_path),
                "HWM_PUBLISHER_ASKPASS_TOKEN_FILE": str(token_path),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            })
            yield env

    def compare_and_set_branch(self, branch: str, expected_head: str, new_head: str) -> bool:
        with self._https_git_auth() as env:
            push = subprocess.run(
                [
                    "git",
                    "-c", "credential.helper=",
                    "push", "--porcelain",
                    f"--force-with-lease=refs/heads/{branch}:{expected_head}",
                    GIT_REMOTE, f"{new_head}:refs/heads/{branch}",
                ],
                cwd=self.repo_root,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        return push.returncode == 0

    def dispatch_ci(self, workflow: str, branch: str, request_id: str, new_head: str) -> dict[str, Any]:
        workflow_q = urllib.parse.quote(workflow, safe="")
        data, _ = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/actions/workflows/{workflow_q}/dispatches",
            {"ref": branch, "inputs": {"request_id": request_id, "new_head": new_head}, "return_run_details": True},
            (200,),
        )
        run_id = (data or {}).get("workflow_run_id")
        return {"run_id": run_id}

    def get_workflow_run(self, run_id: int) -> dict[str, Any]:
        for attempt in range(6):
            try:
                data, _ = self._request("GET", f"/repos/{self.owner}/{self.repo}/actions/runs/{run_id}")
                return data
            except RuntimeError:
                if attempt == 5:
                    raise
                time.sleep(1)
        raise RuntimeError("workflow run unavailable")

    def _iter_repository_comments(self) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 51):
            data, _ = self._request(
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
            if (
                user.get("id") != PUBLISHER_RESULT_AUTHOR["github_account_id"]
                or user.get("login") != PUBLISHER_RESULT_AUTHOR["login"]
            ):
                continue
            try:
                obj = json.loads(comment.get("body", ""))
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("schema") == RESULT_SCHEMA and obj.get("request_id") == request_id:
                results.append(obj)
        return results

    def find_request_fingerprints(self, request_id: str) -> list[str]:
        out: list[str] = []
        for comment in self._iter_repository_comments():
            user = comment.get("user") or {}
            if user.get("id") != ALLOWED_AUTHOR["github_account_id"] or user.get("login") != ALLOWED_AUTHOR["login"]:
                continue
            try:
                kind, request = parse_transport_comment(comment.get("body", ""))
            except PublishFailure:
                continue
            if kind == "request" and request and request.get("request_id") == request_id:
                out.append(request_fingerprint(request))
        return out

    def post_result(self, issue_number: int, result: dict[str, Any]) -> None:
        self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/issues/{issue_number}/comments",
            {"body": canonical_json(result)},
            (201,),
        )
