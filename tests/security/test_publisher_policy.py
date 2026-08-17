from security.publisher_test_support import *  # noqa: F401,F403

class PublisherPolicy(PublisherSecurityBase):
    def test_transport_exact_author_allowlist(self):
        cases = [
            {"id": ALLOWED_AUTHOR["github_account_id"], "login": "Other"},
            {"id": 999, "login": ALLOWED_AUTHOR["login"]},
            {"id": 41898282, "login": "github-actions[bot]"},
        ]
        for author in cases:
            with self.subTest(author=author):
                result = self.publish(author=author)
                self.assertEqual(result["error"]["code"], "UNAUTHORIZED_AUTHOR")

    def test_wrong_issue_and_pr_comment_rejected(self):
        self.assertEqual(self.publish(issue=14)["error"]["code"], "BRANCH_TASK_MISMATCH")
        self.assertEqual(self.publish(pull_request=True)["error"]["code"], "BRANCH_TASK_MISMATCH")

    def test_result_comment_is_not_recursive_request(self):
        body = canonical_json({"schema": "hwm-publish-result/bootstrap-v1", "request_id": "pub-0013-0001"})
        self.assertIsNone(self.publisher.handle_event(event(request(), body=body, author={"id": 1, "login": "bot"})))
        self.assertEqual(preflight_concurrency(event(request(), body=body))["should_run"], "false")

    def test_malformed_and_multiple_envelopes_rejected(self):
        for body in ("not-json", canonical_json(request()) + "\n" + canonical_json(request(request_id="pub-0013-0002")), "[]"):
            with self.subTest(body=body[:20]):
                result = self.publisher.handle_event(event(request(), body=body))
                self.assertEqual(result["error"]["code"], "INVALID_SCHEMA")

    def test_wrong_repository_rejected_including_control_and_context(self):
        for repo in ("Dsamofalov/hwm-control", "Dsamofalov/hwm-context"):
            req = request(repository=repo)
            result = self.publisher.handle_event(event(req, repository=repo))
            self.assertEqual(result["error"]["code"], "REPOSITORY_NOT_ALLOWED")

    def test_task_must_be_open_claimed_and_branch_number_exact(self):
        self.backend.issues[13]["labels"] = [{"name": "ready"}]
        self.assertEqual(self.publish()["error"]["code"], "TASK_NOT_CLAIMED")
        self.backend.issues[13]["labels"] = [{"name": "claimed"}]
        bad = request(branch="agent/infra-0014-wrong")
        self.assertEqual(self.publish(bad)["error"]["code"], "BRANCH_TASK_MISMATCH")

    def test_issue_recorded_branch_identity_must_match(self):
        self.backend.issues[13]["body"] = "branch: `agent/infra-0013-other`"
        self.assertEqual(self.publish()["error"]["code"], "BRANCH_TASK_MISMATCH")

    def test_default_branch_forbidden(self):
        req = request(branch="main")
        self.assertEqual(self.publish(req)["error"]["code"], "FORBIDDEN_TARGET")

    def test_missing_and_protected_task_branch_rejected(self):
        missing = request(branch="agent/infra-0013-missing")
        self.assertEqual(self.publish(missing)["error"]["code"], "BRANCH_TASK_MISMATCH")
        self.setUp()
        branch = request()["task_branch"]
        self.backend.protected_branches.add(branch)
        self.assertEqual(self.publish()["error"]["code"], "FORBIDDEN_TARGET")

    def test_add_replace_and_path_state_preconditions(self):
        add = self.publish()
        self.assertEqual(add["status"], "success")
        # fresh backend for replace
        self.setUp()
        self.backend.trees[TREE] = [{"path": "sandbox/existing.txt", "mode": "100644", "type": "blob", "sha": OLD}]
        rep = request(changes=[{"op": "replace", "path": "sandbox/existing.txt", "blob_sha": NEW, "mode": "100644", "expected_blob_sha": OLD}])
        self.assertEqual(self.publish(rep)["status"], "success")
        self.setUp(); self.backend.trees[TREE] = [{"path": "sandbox/existing.txt", "mode": "100644", "type": "blob", "sha": OLD}]
        bad = request(changes=[{"op": "add", "path": "sandbox/existing.txt", "blob_sha": NEW, "mode": "100644"}])
        self.assertEqual(self.publish(bad)["error"]["code"], "PATH_STATE_MISMATCH")
        self.setUp(); self.backend.trees[TREE] = [{"path": "sandbox/existing.txt", "mode": "100644", "type": "blob", "sha": OLD}]
        bad = request(changes=[{"op": "replace", "path": "sandbox/existing.txt", "blob_sha": NEW, "mode": "100644", "expected_blob_sha": RACE}])
        self.assertEqual(self.publish(bad)["error"]["code"], "PATH_STATE_MISMATCH")

    def test_nonexistent_and_non_blob_objects_rejected(self):
        bad = request(changes=[{"op": "add", "path": "sandbox/x.txt", "blob_sha": sha("missing"), "mode": "100644"}])
        self.assertEqual(self.publish(bad)["error"]["code"], "BLOB_NOT_FOUND")
        self.setUp()
        bad = request(changes=[{"op": "add", "path": "sandbox/x.txt", "blob_sha": TREE, "mode": "100644"}])
        self.assertEqual(self.publish(bad)["error"]["code"], "BLOB_NOT_REGULAR")

    def test_replace_of_symlink_or_gitlink_state_rejected(self):
        for mode, typ in (("120000", "blob"), ("160000", "commit")):
            self.setUp()
            self.backend.trees[TREE] = [{"path": "sandbox/existing", "mode": mode, "type": typ, "sha": OLD}]
            req = request(changes=[{"op": "replace", "path": "sandbox/existing", "blob_sha": NEW, "mode": "100644", "expected_blob_sha": OLD}])
            with self.subTest(mode=mode): self.assertEqual(self.publish(req)["error"]["code"], "BLOB_NOT_REGULAR")

    def test_path_traversal_workflow_action_codeowners_and_self_modification_forbidden(self):
        paths = [
            "../escape", "a/../escape", "/absolute", "a//b", "a\\b",
            ".github/workflows/pwn.yml", ".github/actions/pwn/action.yml", "pkg/action.yaml",
            "docs/CODEOWNERS", "control/task_branch_publisher.py", "control/publisher_credentials.json",
            "schemas/publish-request.bootstrap-v1.schema.json",
        ]
        for path in paths:
            self.setUp()
            req = request(changes=[{"op": "add", "path": path, "blob_sha": NEW, "mode": "100644"}])
            with self.subTest(path=path): self.assertEqual(self.publish(req)["error"]["code"], "FORBIDDEN_PATH")

    def test_malicious_blob_is_inert_data_and_never_executed(self):
        marker = Path(tempfile.gettempdir()) / "hwm-publisher-malicious-marker"
        try: marker.unlink()
        except FileNotFoundError: pass
        # Fake backend stores only object type; publisher has no API to execute candidate payload.
        req = request(changes=[{"op": "add", "path": "sandbox/malicious.py", "blob_sha": MAL, "mode": "100755"}])
        result = self.publish(req)
        self.assertEqual(result["status"], "success")
        self.assertFalse(marker.exists())

    def test_ci_dispatch_failure_is_explicit_sanitized_error(self):
        self.backend.dispatch_failure = True
        result = self.publish()
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error"]["code"], "CI_DISPATCH_FAILED")
        self.assertNotIn("secret", canonical_json(result).lower())
        self.assertNotIn("new_head", result)

    def test_ci_run_head_mismatch_is_not_validation(self):
        self.backend.dispatch_head_override = RACE
        result = self.publish()
        self.assertEqual(result["error"]["code"], "CI_DISPATCH_FAILED")

