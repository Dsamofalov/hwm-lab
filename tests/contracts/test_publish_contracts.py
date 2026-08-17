import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[2]
REQ_SCHEMA = json.loads((ROOT / "schemas" / "publish-request.bootstrap-v1.schema.json").read_text())
RES_SCHEMA = json.loads((ROOT / "schemas" / "publish-result.bootstrap-v1.schema.json").read_text())
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "89abcdef0123456789abcdef0123456789abcdef"
FP = "a" * 64

VALID_ADD = {
    "schema": "hwm-publish-request/bootstrap-v1",
    "request_id": "pub-0013-add",
    "repository": "Dsamofalov/hwm-lab",
    "task_issue": 13,
    "task_branch": "agent/infra-0013-controlled-task-branch-publisher",
    "expected_head": SHA,
    "changes": [{"op": "add", "path": "sandbox/inert.txt", "blob_sha": SHA2, "mode": "100644"}],
    "ci": {"workflow": "infrastructure-ci.yml"},
}
VALID_REPLACE = copy.deepcopy(VALID_ADD)
VALID_REPLACE["request_id"] = "pub-0013-replace"
VALID_REPLACE["changes"] = [{
    "op": "replace", "path": "sandbox/inert.txt", "blob_sha": SHA2,
    "mode": "100755", "expected_blob_sha": SHA,
}]
SUCCESS = {
    "schema": "hwm-publish-result/bootstrap-v1",
    "request_id": "pub-0013-add",
    "status": "success",
    "repository": "Dsamofalov/hwm-lab",
    "task_issue": 13,
    "task_branch": "agent/infra-0013-controlled-task-branch-publisher",
    "expected_head": SHA,
    "observed_head_before": SHA,
    "new_head": SHA2,
    "commit_sha": SHA2,
    "changes": copy.deepcopy(VALID_ADD["changes"]),
    "request_fingerprint": FP,
    "idempotent_replay": False,
    "ci_dispatch": {"workflow": "infrastructure-ci.yml", "run_id": 123, "head_sha": SHA2},
}
ERROR = {
    "schema": "hwm-publish-result/bootstrap-v1",
    "request_id": "pub-0013-add",
    "status": "error",
    "repository": "Dsamofalov/hwm-lab",
    "task_issue": 13,
    "task_branch": "agent/infra-0013-controlled-task-branch-publisher",
    "expected_head": SHA,
    "observed_head_before": SHA,
    "request_fingerprint": FP,
    "idempotent_replay": False,
    "error": {"code": "EXPECTED_HEAD_MISMATCH", "message": "remote head changed", "retryable": False},
}


def validate(schema, value):
    Draft202012Validator(schema).validate(value)


class PublishSchemas(unittest.TestCase):
    def bad(self, schema, value):
        with self.assertRaises(ValidationError):
            validate(schema, value)

    def test_schema_documents(self):
        Draft202012Validator.check_schema(REQ_SCHEMA)
        Draft202012Validator.check_schema(RES_SCHEMA)

    def test_positive_add_replace_success_error_and_replay(self):
        validate(REQ_SCHEMA, VALID_ADD)
        validate(REQ_SCHEMA, VALID_REPLACE)
        validate(RES_SCHEMA, SUCCESS)
        validate(RES_SCHEMA, ERROR)
        replay = copy.deepcopy(SUCCESS); replay["idempotent_replay"] = True
        validate(RES_SCHEMA, replay)

    def test_closed_request_and_result(self):
        obj = copy.deepcopy(VALID_ADD); obj["command"] = "echo nope"; self.bad(REQ_SCHEMA, obj)
        obj = copy.deepcopy(SUCCESS); obj["token"] = "secret"; self.bad(RES_SCHEMA, obj)

    def test_missing_required(self):
        for field in ("request_id", "repository", "task_issue", "task_branch", "expected_head", "changes", "ci"):
            obj = copy.deepcopy(VALID_ADD); del obj[field]
            with self.subTest(field=field): self.bad(REQ_SCHEMA, obj)

    def test_wrong_schema_and_sha_syntax(self):
        obj = copy.deepcopy(VALID_ADD); obj["schema"] = "hwm-job/v1"; self.bad(REQ_SCHEMA, obj)
        for bad in ("HEAD", "ABCDEF" * 7, "0" * 39, "g" * 40):
            obj = copy.deepcopy(VALID_ADD); obj["expected_head"] = bad
            with self.subTest(bad=bad): self.bad(REQ_SCHEMA, obj)

    def test_malformed_repository_issue_and_branch_identities(self):
        cases = [
            ("repository", "Dsamofalov"),
            ("repository", "Dsamofalov/hwm lab"),
            ("task_issue", 0),
            ("task_issue", "13"),
            ("task_branch", " agent/infra-0013-x"),
            ("task_branch", "agent/infra-0013-x "),
            ("task_branch", "agent//infra-0013-x"),
            ("task_branch", "agent/infra-0013-x\nmain"),
        ]
        for field, value in cases:
            obj = copy.deepcopy(VALID_ADD); obj[field] = value
            with self.subTest(field=field, value=value): self.bad(REQ_SCHEMA, obj)

    def test_unknown_or_forbidden_operation_shapes(self):
        for op in ("delete", "rename", "copy", "tree", "symlink", "gitlink"):
            obj = copy.deepcopy(VALID_ADD); obj["changes"][0]["op"] = op
            with self.subTest(op=op): self.bad(REQ_SCHEMA, obj)

    def test_non_regular_modes(self):
        for mode in ("040000", "120000", "160000", "100600"):
            obj = copy.deepcopy(VALID_ADD); obj["changes"][0]["mode"] = mode
            with self.subTest(mode=mode): self.bad(REQ_SCHEMA, obj)

    def test_replace_requires_expected_blob_sha(self):
        obj = copy.deepcopy(VALID_REPLACE); del obj["changes"][0]["expected_blob_sha"]
        self.bad(REQ_SCHEMA, obj)

    def test_add_must_not_carry_replace_precondition(self):
        obj = copy.deepcopy(VALID_ADD); obj["changes"][0]["expected_blob_sha"] = SHA
        self.bad(REQ_SCHEMA, obj)

    def test_error_codes_are_closed(self):
        obj = copy.deepcopy(ERROR); obj["error"]["code"] = "SOMETHING_ELSE"
        self.bad(RES_SCHEMA, obj)

    def test_failure_cannot_fabricate_publication_fields(self):
        for field, value in (("new_head", SHA2), ("commit_sha", SHA2), ("changes", VALID_ADD["changes"]),
                             ("ci_dispatch", SUCCESS["ci_dispatch"])):
            obj = copy.deepcopy(ERROR); obj[field] = value
            with self.subTest(field=field): self.bad(RES_SCHEMA, obj)

    def test_success_requires_exact_ci_association(self):
        for field in ("new_head", "commit_sha", "changes", "ci_dispatch"):
            obj = copy.deepcopy(SUCCESS); del obj[field]
            with self.subTest(field=field): self.bad(RES_SCHEMA, obj)
        obj = copy.deepcopy(SUCCESS); obj["ci_dispatch"]["workflow"] = "other.yml"; self.bad(RES_SCHEMA, obj)


if __name__ == "__main__":
    unittest.main()
