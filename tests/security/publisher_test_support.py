import copy
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))

from task_branch_publisher import (  # noqa: E402
    ALLOWED_AUTHOR,
    Publisher,
    canonical_json,
    path_forbidden,
    preflight_concurrency,
    request_fingerprint,
)


def sha(label):
    return hashlib.sha1(label.encode()).hexdigest()


BASE = sha("base")
BASE2 = sha("base2")
OLD = sha("old")
NEW = sha("new")
MAL = sha("malicious")
TREE = sha("tree")
RACE = sha("race")


def request(issue=13, branch="agent/infra-0013-controlled-task-branch-publisher", expected=BASE,
            request_id="pub-0013-0001", repository="Dsamofalov/hwm-lab", changes=None):
    return {
        "schema": "hwm-publish-request/bootstrap-v1",
        "request_id": request_id,
        "repository": repository,
        "task_issue": issue,
        "task_branch": branch,
        "expected_head": expected,
        "changes": changes or [{"op": "add", "path": "sandbox/inert.txt", "blob_sha": NEW, "mode": "100644"}],
        "ci": {"workflow": "infrastructure-ci.yml"},
    }


def event(req, issue=None, author=None, body=None, repository=None, pull_request=False):
    author = author or {"id": ALLOWED_AUTHOR["github_account_id"], "login": ALLOWED_AUTHOR["login"], "type": "User"}
    issue_obj = {"number": req.get("task_issue") if issue is None else issue}
    if pull_request:
        issue_obj["pull_request"] = {"url": "https://example.invalid"}
    return {
        "repository": {"full_name": repository or req.get("repository")},
        "issue": issue_obj,
        "comment": {"id": 9001, "body": body if body is not None else canonical_json(req), "user": author},
    }


class FakeBackend:
    def __init__(self):
        self.repo = {"default_branch": "main"}
        self.issues = {
            13: {"state": "open", "labels": [{"name": "claimed"}], "body": "branch: `agent/infra-0013-controlled-task-branch-publisher`"},
            14: {"state": "open", "labels": [{"name": "claimed"}], "body": "branch: `agent/infra-0014-sandbox-a`"},
            15: {"state": "open", "labels": [{"name": "claimed"}], "body": "branch: `agent/infra-0015-sandbox-b`"},
        }
        self.branches = {
            "agent/infra-0013-controlled-task-branch-publisher": BASE,
            "agent/infra-0014-sandbox-a": BASE,
            "agent/infra-0015-sandbox-b": BASE2,
        }
        self.commits = {
            BASE: {"tree": {"sha": TREE}, "parents": []},
            BASE2: {"tree": {"sha": TREE}, "parents": []},
        }
        self.trees = {TREE: []}
        self.object_kinds = {NEW: "blob", MAL: "blob", OLD: "blob", TREE: "tree"}
        self.results = []
        self.request_fingerprints = {}
        self.cas_calls = []
        self.dispatch_calls = []
        self.created_commits = []
        self.race_branch = None
        self.protected_branches = set()
        self.dispatch_failure = False
        self.dispatch_head_override = None
        self._lock = threading.Lock()
        self.active_create = 0
        self.max_active_create = 0
        self.create_delay = 0

    def get_repository(self): return copy.deepcopy(self.repo)
    def get_issue(self, number): return copy.deepcopy(self.issues[number])
    def branch_exists(self, branch): return branch in self.branches
    def branch_is_protected(self, branch): return branch in self.protected_branches
    def get_branch_head(self, branch): return self.branches[branch]
    def get_commit(self, commit_sha): return copy.deepcopy(self.commits[commit_sha])
    def get_tree(self, tree_sha): return copy.deepcopy(self.trees[tree_sha])
    def object_kind(self, object_sha): return self.object_kinds.get(object_sha)

    def create_candidate_commit(self, branch, expected_head, changes, message):
        with self._lock:
            self.active_create += 1
            self.max_active_create = max(self.max_active_create, self.active_create)
        try:
            if self.create_delay:
                time.sleep(self.create_delay)
            value = sha(message + expected_head + canonical_json(changes) + str(len(self.created_commits)))
            self.commits[value] = {"tree": {"sha": sha("candidate-tree:" + value)}, "parents": [{"sha": expected_head}]}
            self.created_commits.append((message, branch, expected_head, copy.deepcopy(changes), value))
            return value
        finally:
            with self._lock:
                self.active_create -= 1

    def local_commit_parent(self, commit_sha):
        parents = self.commits[commit_sha].get("parents", [])
        return parents[0]["sha"] if len(parents) == 1 else None

    def compare_and_set_branch(self, branch, expected_head, new_head):
        with self._lock:
            self.cas_calls.append((branch, expected_head, new_head))
            if self.race_branch == branch:
                self.branches[branch] = RACE
                self.race_branch = None
            if self.branches.get(branch) != expected_head:
                return False
            self.branches[branch] = new_head
            return True

    def dispatch_ci(self, workflow, branch, request_id, new_head):
        if self.dispatch_failure:
            raise RuntimeError("dispatch unavailable with secret=do-not-leak")
        run_id = 1000 + len(self.dispatch_calls)
        self.dispatch_calls.append((workflow, branch, request_id, new_head, run_id))
        return {"run_id": run_id}

    def get_workflow_run(self, run_id):
        call = next(item for item in self.dispatch_calls if item[-1] == run_id)
        return {
            "id": run_id,
            "head_sha": self.dispatch_head_override or call[3],
            "event": "workflow_dispatch",
            "path": ".github/workflows/infrastructure-ci.yml",
        }

    def find_results(self, request_id):
        return [copy.deepcopy(item) for item in self.results if item.get("request_id") == request_id]

    def find_request_fingerprints(self, request_id):
        return list(self.request_fingerprints.get(request_id, []))


class PublisherSecurityBase(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.publisher = Publisher(self.backend, manifest={
            "schema": "hwm-publisher-protected-paths/bootstrap-v1",
            "exact_paths": ["control/task_branch_publisher.py", "schemas/publish-request.bootstrap-v1.schema.json"],
            "prefixes": ["control/publisher_"],
        })

    def publish(self, req=None, **event_kwargs):
        req = req or request()
        return self.publisher.handle_event(event(req, **event_kwargs))

