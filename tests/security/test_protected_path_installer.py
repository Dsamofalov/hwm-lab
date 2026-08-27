import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))

from protected_path_installer import Installer  # noqa: E402
from protected_path_installer_backend import ExpectedHeadChanged  # noqa: E402
from protected_path_installer_contract import (  # noqa: E402
    InstallFailure,
    canonical_json,
    request_fingerprint,
    validate_request_shape,
)
from protected_path_installer_policy import (  # noqa: E402
    issue_installation_branch,
    validate_candidate_workflow,
    validate_protected_path,
)

BASE = "1" * 40
CANDIDATE = "2" * 40
BASE_TREE = "3" * 40
CANDIDATE_TREE = "4" * 40
BLOB = "5" * 40
OLD_BLOB = "6" * 40
RACE = "7" * 40
BRANCH = "agent/infra-0087-protected-path-installer-acceptance"
PATH = ".github/workflows/i10-0087-protected-path-installer-acceptance.yml"
PIN = "3d3c42e5aac5ba805825da76410c181273ba90b1"
GOOD_WORKFLOW = f"""name: Disposable protected path acceptance

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  acceptance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN} # v7.0.1
        with:
          persist-credentials: false
      - run: echo acceptance
""".encode()


def architecture_body(branch: str = BRANCH, runtime_path: str = PATH) -> str:
    return f"""## Ownership
Task id: `I10-0087`
Claimed branch: `agent/infra-0087-protected-path-installer-install`
Protected-path installation branch: `{branch}`

## Runtime protected-path allowlist
- `{runtime_path}`
"""


def architecture_issue(branch: str = BRANCH, runtime_path: str = PATH) -> dict:
    return {
        "state": "open",
        "labels": [
            {"name": "claimed"},
            {"name": "architecture"},
            {"name": "trusted"},
            {"name": "contract"},
        ],
        "assignees": [{"id": 25666939, "login": "Dsamofalov"}],
        "body": architecture_body(branch, runtime_path),
    }


def request(**updates) -> dict:
    value = {
        "schema": "hwm-protected-path-install-request/bootstrap-v1",
        "request_id": "i10-0087-accept-positive-v1",
        "repository": "Dsamofalov/hwm-lab",
        "architecture_issue": 87,
        "task_id": "I10-0087",
        "installation_branch": BRANCH,
        "expected_head": BASE,
        "protected_main_base_sha": BASE,
        "issue_declared_paths": [PATH],
        "changes": [{"op": "add", "path": PATH, "blob_sha": BLOB, "mode": "100644"}],
        "commit_message": "I10-0087 disposable protected-path acceptance",
        "trusted_validation": {
            "workflow": "protected-path-installer.yml",
            "required_check": "protected-path-installer/trusted-static",
            "protected_source_ref": "refs/heads/main",
        },
    }
    value.update(updates)
    return value


def event(req: dict | None = None, *, owner: bool = True, association: str = "OWNER") -> dict:
    req = req or request()
    return {
        "repository": {"full_name": "Dsamofalov/hwm-lab"},
        "issue": {"number": 901, "title": "Disposable #87 acceptance carrier"},
        "comment": {
            "id": 99001,
            "author_association": association,
            "user": {"id": 25666939 if owner else 999, "login": "Dsamofalov" if owner else "intruder"},
            "body": canonical_json(req),
        },
    }


class FakeBackend:
    def __init__(self):
        self.default_branch = "main"
        self.branches = {"main": BASE, BRANCH: BASE}
        self.issue = architecture_issue()
        self.results = []
        self.request_fingerprints = []
        self.calls = []
        self.candidate_calls = 0
        self.validation_calls = 0
        self.cas_calls = 0
        self.race = False
        self.validation_failure = None
        self.object_kind_value = "blob"
        self.base_entries = [
            {"path": ".github", "type": "tree", "mode": "040000", "sha": "8" * 40},
            {"path": ".github/workflows", "type": "tree", "mode": "040000", "sha": "9" * 40},
            {"path": "README.md", "type": "blob", "mode": "100644", "sha": OLD_BLOB},
        ]
        self.candidate_entries = [
            {"path": ".github", "type": "tree", "mode": "040000", "sha": "a" * 40},
            {"path": ".github/workflows", "type": "tree", "mode": "040000", "sha": "b" * 40},
            {"path": "README.md", "type": "blob", "mode": "100644", "sha": OLD_BLOB},
            {"path": PATH, "type": "blob", "mode": "100644", "sha": BLOB},
        ]
        self.comments = {99001: event()["comment"] | {"issue_url": "https://api.github.com/repos/Dsamofalov/hwm-lab/issues/901"}}

    def get_repository(self):
        return {"default_branch": self.default_branch}

    def get_architecture_issue(self, number):
        if number == 87:
            return copy.deepcopy(self.issue)
        wrong = architecture_issue()
        wrong["body"] = wrong["body"].replace("I10-0087", "I10-0086")
        return wrong

    def branch_exists(self, branch):
        return branch in self.branches

    def get_branch_head(self, branch):
        return self.branches[branch]

    def get_main_head(self):
        return self.branches["main"]

    def get_commit(self, sha):
        if sha == BASE:
            return {"tree": {"sha": BASE_TREE}, "parents": []}
        if sha == CANDIDATE:
            return {"tree": {"sha": CANDIDATE_TREE}, "parents": [{"sha": BASE}]}
        raise AssertionError(f"unexpected commit {sha}")

    def get_tree(self, sha):
        if sha == BASE_TREE:
            return copy.deepcopy(self.base_entries)
        if sha == CANDIDATE_TREE:
            return copy.deepcopy(self.candidate_entries)
        raise AssertionError(f"unexpected tree {sha}")

    def object_kind(self, sha):
        return self.object_kind_value if sha == BLOB else None

    def create_candidate_commit(self, expected_head, changes, message):
        self.calls.append("candidate")
        self.candidate_calls += 1
        self.candidate_entries = copy.deepcopy(self.base_entries)
        for change in changes:
            self.candidate_entries.append(
                {"path": change["path"], "type": "blob", "mode": change["mode"], "sha": change["blob_sha"]}
            )
        return CANDIDATE

    def dispatch_trusted_validation(self, **kwargs):
        self.calls.append("validation")
        self.validation_calls += 1
        if self.validation_failure is not None:
            raise self.validation_failure
        return {
            "workflow": "protected-path-installer.yml",
            "required_check": "protected-path-installer/trusted-static",
            "run_id": 321,
            "head_sha": CANDIDATE,
            "source_ref": "refs/heads/main",
        }

    def compare_and_set_branch(self, branch, expected_head, new_head):
        self.calls.append("cas")
        self.cas_calls += 1
        if self.race:
            self.branches[branch] = RACE
            raise ExpectedHeadChanged()
        if self.branches[branch] != expected_head:
            raise ExpectedHeadChanged()
        self.branches[branch] = new_head

    def find_results(self, request_id):
        return [copy.deepcopy(item) for item in self.results if item.get("request_id") == request_id]

    def find_request_fingerprints(self, request_id):
        return list(self.request_fingerprints)

    def get_issue_comment(self, comment_id):
        return copy.deepcopy(self.comments[comment_id])

    def comment_belongs_to_issue(self, comment, issue_number):
        return comment.get("issue_url") == f"https://api.github.com/repos/Dsamofalov/hwm-lab/issues/{issue_number}"

    def get_blob_bytes(self, sha):
        if sha != BLOB:
            raise AssertionError("unexpected blob")
        return GOOD_WORKFLOW


class ProtectedPathInstallerSecurity(unittest.TestCase):
    def setUp(self):
        self.backend = FakeBackend()
        self.installer = Installer(self.backend)

    def publish(self, req=None, **event_kwargs):
        return self.installer.handle_event(event(req, **event_kwargs))

    def test_positive_owner_claim_validates_before_nonforce_cas(self):
        result = self.publish()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["observed_head_before"], BASE)
        self.assertEqual(result["new_head"], CANDIDATE)
        self.assertEqual(self.backend.branches[BRANCH], CANDIDATE)
        self.assertEqual(self.backend.calls, ["candidate", "validation", "cas"])

    def test_exact_actor_and_owner_association_are_required(self):
        result = self.publish(owner=False)
        self.assertEqual(result["error"]["code"], "UNAUTHORIZED_AUTHOR")
        self.assertEqual(self.backend.calls, [])
        result = self.publish(association="MEMBER")
        self.assertEqual(result["error"]["code"], "UNAUTHORIZED_AUTHOR")
        self.assertEqual(self.backend.calls, [])

    def test_issue_claim_labels_task_branch_and_architecture_issue_bindings(self):
        self.backend.issue["labels"] = [{"name": "claimed"}, {"name": "architecture"}, {"name": "trusted"}]
        result = self.publish()
        self.assertEqual(result["error"]["code"], "REQUIRED_LABEL_MISSING")
        self.assertEqual(self.backend.calls, [])
        self.backend.issue = architecture_issue()
        result = self.publish(request(task_id="I10-0086"))
        self.assertEqual(result["error"]["code"], "ISSUE_TASK_BRANCH_MISMATCH")
        result = self.publish(request(architecture_issue=86))
        self.assertEqual(result["error"]["code"], "ISSUE_TASK_BRANCH_MISMATCH")
        self.assertEqual(self.backend.calls, [])

    def test_wrong_repository_and_protected_main_base_are_rejected(self):
        result = self.publish(request(repository="Dsamofalov/hwm-control"))
        self.assertEqual(result["error"]["code"], "REPOSITORY_NOT_ALLOWED")
        result = self.publish(request(protected_main_base_sha="0" * 40))
        self.assertEqual(result["error"]["code"], "PROTECTED_MAIN_BASE_MISMATCH")
        self.assertEqual(self.backend.calls, [])

    def test_default_branch_target_is_rejected(self):
        self.backend.default_branch = BRANCH
        result = self.publish()
        self.assertEqual(result["error"]["code"], "DEFAULT_BRANCH_FORBIDDEN")
        self.assertEqual(self.backend.calls, [])

    def test_undeclared_and_normalized_paths_fail_closed(self):
        other = ".github/workflows/not-declared.yml"
        req = request(changes=[{"op": "add", "path": other, "blob_sha": BLOB, "mode": "100644"}])
        result = self.publish(req)
        self.assertEqual(result["error"]["code"], "UNDECLARED_PATH")
        with self.assertRaises(InstallFailure) as raised:
            validate_protected_path(".github/workflows/../escape.yml", [".github/workflows/../escape.yml"])
        self.assertEqual(raised.exception.code, "PATH_CLASS_FORBIDDEN")

    def test_self_publisher_bootstrap_and_codeowners_are_absolute_denials(self):
        cases = [
            (".github/workflows/protected-path-installer.yml", "SELF_MODIFICATION_FORBIDDEN"),
            (".github/workflows/task-branch-publisher.yml", "ORDINARY_PUBLISHER_MODIFICATION_FORBIDDEN"),
            (".github/workflows/repository-bootstrap-ci.yml", "BOOTSTRAP_WORKFLOW_MODIFICATION_FORBIDDEN"),
            (".github/CODEOWNERS", "CODEOWNERS_FORBIDDEN"),
        ]
        for path, code in cases:
            with self.subTest(path=path), self.assertRaises(InstallFailure) as raised:
                validate_protected_path(path, [path])
            self.assertEqual(raised.exception.code, code)

    def test_rules_settings_secret_and_environment_paths_are_absolute_denials(self):
        cases = [
            (".github/rulesets/main.json", "RULESET_OR_SETTINGS_FORBIDDEN"),
            (".github/settings/repository.yml", "RULESET_OR_SETTINGS_FORBIDDEN"),
            (".github/actions/secrets/action.yml", "SECRET_OR_ENVIRONMENT_PATH_FORBIDDEN"),
            (".github/actions/environments/action.yml", "SECRET_OR_ENVIRONMENT_PATH_FORBIDDEN"),
        ]
        for path, code in cases:
            with self.subTest(path=path), self.assertRaises(InstallFailure) as raised:
                validate_protected_path(path, [path])
            self.assertEqual(raised.exception.code, code)

    def test_delete_symlink_gitlink_and_replace_preconditions_are_rejected(self):
        bad = request()
        bad["changes"] = [{"op": "delete", "path": PATH, "blob_sha": BLOB, "mode": "100644"}]
        with self.assertRaises(InstallFailure) as raised:
            validate_request_shape(bad)
        self.assertEqual(raised.exception.code, "INVALID_SCHEMA")
        for mode in ("120000", "160000"):
            bad = request()
            bad["changes"][0]["mode"] = mode
            with self.assertRaises(InstallFailure):
                validate_request_shape(bad)
        replace = request(changes=[{
            "op": "replace", "path": PATH, "blob_sha": BLOB, "mode": "100644", "expected_blob_sha": OLD_BLOB,
        }])
        result = self.publish(replace)
        self.assertEqual(result["error"]["code"], "PATH_STATE_MISMATCH")
        self.assertEqual(self.backend.calls, [])

    def test_stale_head_creates_no_candidate_validation_or_ref_move(self):
        self.backend.branches[BRANCH] = RACE
        result = self.publish()
        self.assertEqual(result["error"]["code"], "EXPECTED_HEAD_MISMATCH")
        self.assertEqual(self.backend.candidate_calls, 0)
        self.assertEqual(self.backend.validation_calls, 0)
        self.assertEqual(self.backend.cas_calls, 0)
        self.assertEqual(self.backend.branches[BRANCH], RACE)

    def test_cas_race_occurs_only_after_trusted_validation_and_does_not_overwrite(self):
        self.backend.race = True
        result = self.publish()
        self.assertEqual(result["error"]["code"], "EXPECTED_HEAD_MISMATCH")
        self.assertEqual(self.backend.calls, ["candidate", "validation", "cas"])
        self.assertEqual(self.backend.branches[BRANCH], RACE)

    def test_changed_payload_under_reused_request_id_is_rejected(self):
        self.backend.request_fingerprints = ["f" * 64]
        result = self.publish()
        self.assertEqual(result["error"]["code"], "REQUEST_ID_REUSE")
        self.assertEqual(self.backend.calls, [])

    def test_identical_success_replay_does_not_create_validate_or_move_ref(self):
        req = request()
        prior = {
            "schema": "hwm-protected-path-install-result/bootstrap-v1",
            "request_id": req["request_id"],
            "status": "success",
            "request_fingerprint": request_fingerprint(req),
            "idempotent_replay": False,
            "new_head": CANDIDATE,
        }
        self.backend.results = [prior]
        result = self.publish(req)
        self.assertTrue(result["idempotent_replay"])
        self.assertEqual(result["new_head"], CANDIDATE)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.branches[BRANCH], BASE)

    def test_static_candidate_workflow_requires_dispatch_read_only_no_secrets_and_exact_pins(self):
        validate_candidate_workflow(PATH, GOOD_WORKFLOW)
        variants = [
            GOOD_WORKFLOW.replace(b"workflow_dispatch:", b"pull_request_target:"),
            GOOD_WORKFLOW.replace(b"contents: read", b"contents: write"),
            GOOD_WORKFLOW + b"\nenv:\n  API: ${{ secrets.API }}\n",
            GOOD_WORKFLOW.replace(PIN.encode(), b"v7"),
        ]
        for raw in variants:
            with self.subTest(raw=raw[:60]), self.assertRaises(InstallFailure) as raised:
                validate_candidate_workflow(PATH, raw)
            self.assertEqual(raised.exception.code, "TRUSTED_VALIDATION_FAILED")

    def test_validation_failure_is_sanitized_and_prevents_cas(self):
        self.backend.validation_failure = InstallFailure(
            "TRUSTED_VALIDATION_FAILED", "Authorization: Bearer should-not-escape"
        )
        result = self.publish()
        self.assertEqual(result["error"]["code"], "TRUSTED_VALIDATION_FAILED")
        self.assertEqual(result["error"]["message"], "sanitized installer diagnostic")
        self.assertEqual(self.backend.calls, ["candidate", "validation"])
        self.assertEqual(self.backend.cas_calls, 0)
        self.assertEqual(self.backend.branches[BRANCH], BASE)

    def test_issue_branch_precedence_and_backend_source_has_no_git_credential_transport(self):
        body = architecture_body().replace(
            f"Protected-path installation branch: `{BRANCH}`",
            f"Protected-path installation branch: `{BRANCH}`\nClaimed branch: `agent/infra-0087-other`",
        )
        self.assertEqual(issue_installation_branch(body), BRANCH)
        source = (ROOT / "control" / "protected_path_installer_backend.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("GIT_ASKPASS", source)
        self.assertNotIn("git push", source)
        self.assertIn('"force": False', source)


if __name__ == "__main__":
    unittest.main()
