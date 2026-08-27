import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[2]
REQ_SCHEMA = json.loads((ROOT / "schemas" / "protected-path-install-request.bootstrap-v1.schema.json").read_text())
RES_SCHEMA = json.loads((ROOT / "schemas" / "protected-path-install-result.bootstrap-v1.schema.json").read_text())
BASE = "0" * 40
HEAD = "1" * 40
BLOB = "2" * 40
OLD = "3" * 40
FP = "a" * 64
PATH = ".github/workflows/i10-0087-protected-path-installer-acceptance.yml"

VALID_ADD = {
    "schema": "hwm-protected-path-install-request/bootstrap-v1",
    "request_id": "i10-0087-accept-positive-v1",
    "repository": "Dsamofalov/hwm-lab",
    "architecture_issue": 87,
    "task_id": "I10-0087",
    "installation_branch": "agent/infra-0087-protected-path-installer-acceptance",
    "expected_head": HEAD,
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
VALID_REPLACE = copy.deepcopy(VALID_ADD)
VALID_REPLACE["request_id"] = "i10-0087-accept-replace-v1"
VALID_REPLACE["changes"] = [{
    "op": "replace",
    "path": PATH,
    "blob_sha": BLOB,
    "mode": "100755",
    "expected_blob_sha": OLD,
}]
SUCCESS = {
    "schema": "hwm-protected-path-install-result/bootstrap-v1",
    "request_id": VALID_ADD["request_id"],
    "status": "success",
    "repository": "Dsamofalov/hwm-lab",
    "architecture_issue": 87,
    "task_id": "I10-0087",
    "installation_branch": VALID_ADD["installation_branch"],
    "expected_head": HEAD,
    "protected_main_base_sha": BASE,
    "observed_head_before": HEAD,
    "new_head": BLOB,
    "commit_sha": BLOB,
    "changes": copy.deepcopy(VALID_ADD["changes"]),
    "trusted_validation": {
        "workflow": "protected-path-installer.yml",
        "required_check": "protected-path-installer/trusted-static",
        "run_id": 123,
        "head_sha": BLOB,
        "source_ref": "refs/heads/main",
    },
    "request_fingerprint": FP,
    "idempotent_replay": False,
}
ERROR = {
    "schema": "hwm-protected-path-install-result/bootstrap-v1",
    "request_id": VALID_ADD["request_id"],
    "status": "error",
    "repository": "Dsamofalov/hwm-lab",
    "architecture_issue": 87,
    "task_id": "I10-0087",
    "installation_branch": VALID_ADD["installation_branch"],
    "expected_head": HEAD,
    "protected_main_base_sha": BASE,
    "observed_head_before": HEAD,
    "request_fingerprint": FP,
    "idempotent_replay": False,
    "error": {"code": "EXPECTED_HEAD_MISMATCH", "message": "head changed", "retryable": False},
}


class ProtectedPathInstallContracts(unittest.TestCase):
    def setUp(self):
        self.req = Draft202012Validator(REQ_SCHEMA)
        self.res = Draft202012Validator(RES_SCHEMA)

    def test_request_add_is_valid(self):
        self.req.validate(VALID_ADD)

    def test_request_replace_is_valid(self):
        self.req.validate(VALID_REPLACE)

    def test_request_rejects_unknown_fields_and_delete(self):
        bad = copy.deepcopy(VALID_ADD)
        bad["extra"] = True
        with self.assertRaises(ValidationError):
            self.req.validate(bad)
        bad = copy.deepcopy(VALID_ADD)
        bad["changes"][0]["op"] = "delete"
        with self.assertRaises(ValidationError):
            self.req.validate(bad)

    def test_request_rejects_traversal_and_non_regular_mode(self):
        bad = copy.deepcopy(VALID_ADD)
        bad["issue_declared_paths"] = [".github/workflows/../x.yml"]
        bad["changes"][0]["path"] = bad["issue_declared_paths"][0]
        with self.assertRaises(ValidationError):
            self.req.validate(bad)
        bad = copy.deepcopy(VALID_ADD)
        bad["changes"][0]["mode"] = "120000"
        with self.assertRaises(ValidationError):
            self.req.validate(bad)

    def test_request_requires_unique_declared_paths_and_exact_source_ref(self):
        bad = copy.deepcopy(VALID_ADD)
        bad["issue_declared_paths"] = [PATH, PATH]
        with self.assertRaises(ValidationError):
            self.req.validate(bad)
        bad = copy.deepcopy(VALID_ADD)
        bad["trusted_validation"]["protected_source_ref"] = "refs/heads/feature"
        with self.assertRaises(ValidationError):
            self.req.validate(bad)

    def test_success_result_is_valid(self):
        self.res.validate(SUCCESS)

    def test_error_result_is_valid(self):
        self.res.validate(ERROR)

    def test_success_requires_validation_and_forbids_error(self):
        bad = copy.deepcopy(SUCCESS)
        del bad["trusted_validation"]
        with self.assertRaises(ValidationError):
            self.res.validate(bad)
        bad = copy.deepcopy(SUCCESS)
        bad["error"] = copy.deepcopy(ERROR["error"])
        with self.assertRaises(ValidationError):
            self.res.validate(bad)

    def test_error_forbids_success_mutation_fields(self):
        bad = copy.deepcopy(ERROR)
        bad["new_head"] = BLOB
        with self.assertRaises(ValidationError):
            self.res.validate(bad)


if __name__ == "__main__":
    unittest.main()
