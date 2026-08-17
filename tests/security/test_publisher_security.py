import re

from security.publisher_test_support import *  # noqa: F401,F403

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class PublisherSecurity(PublisherSecurityBase):
    def test_preflight_concurrency_key_is_branch_local_and_unauthorized_never_mints_privileged_job(self):
        a = request(issue=14, branch="agent/infra-0014-sandbox-a", request_id="pub-0014-aaaa")
        b = request(issue=15, branch="agent/infra-0015-sandbox-b", expected=BASE2, request_id="pub-0015-bbbb")
        a2 = copy.deepcopy(a); a2["request_id"] = "pub-0014-cccc"
        self.assertEqual(preflight_concurrency(event(a))["concurrency_key"], preflight_concurrency(event(a2))["concurrency_key"])
        self.assertNotEqual(preflight_concurrency(event(a))["concurrency_key"], preflight_concurrency(event(b))["concurrency_key"])
        denied = event(a, author={"id": 999, "login": "collaborator"})
        self.assertEqual(preflight_concurrency(denied)["should_run"], "false")

    def test_implementation_has_real_lease_and_no_candidate_execution_primitives(self):
        source = "\n".join(
            (ROOT / "control" / name).read_text()
            for name in ("task_branch_publisher.py", "publisher_backend.py", "publisher_contract.py", "publisher_policy.py")
        )
        self.assertIn("--force-with-lease=refs/heads/", source)
        self.assertIn("hash-object", source)
        self.assertIn("update-index", source)
        self.assertIn("commit-tree", source)
        self.assertNotIn('"checkout"', source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("exec(", source)
        self.assertNotIn("importlib", source)

    def test_publisher_workflow_uses_job_scoped_builtin_token_and_no_long_lived_write_secret(self):
        workflow = (ROOT / ".github" / "workflows" / "task-branch-publisher.yml").read_text()
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("issues: write", workflow)
        self.assertIn("actions: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertNotIn("administration: write", workflow)
        self.assertNotIn("workflows: write", workflow)
        self.assertNotIn("create-github-app-token", workflow)
        self.assertNotIn("HWM_PUBLISHER_DEPLOY_KEY", workflow)
        self.assertNotIn("secrets.HWM_PUBLISHER", workflow)
        self.assertIn("HWM_PUBLISHER_TOKEN: ${{ github.token }}", workflow)
        self.assertGreaterEqual(workflow.count("ref: ${{ github.sha }}"), 2)
        self.assertNotIn("ref: ${{ needs.preflight.outputs", workflow)
        self.assertGreaterEqual(workflow.count("persist-credentials: false"), 2)
        self.assertIn("cancel-in-progress: false", workflow)

    def test_ordinary_ci_is_read_only_exact_head_dispatch_and_has_no_publisher_credentials(self):
        ci = (ROOT / ".github" / "workflows" / "infrastructure-ci.yml").read_text()
        self.assertIn("permissions:\n  contents: read", ci)
        self.assertIn("workflow_dispatch:", ci)
        self.assertIn("EXPECTED_HEAD: ${{ inputs.new_head }}", ci)
        self.assertIn("test \"$GITHUB_SHA\" = \"$EXPECTED_HEAD\"", ci)
        self.assertIn("git rev-parse HEAD", ci)
        self.assertNotIn("HWM_PUBLISHER_DEPLOY_KEY", ci)
        self.assertNotIn("HWM_PUBLISHER_TOKEN", ci)
        self.assertNotIn("contents: write", ci)
        self.assertIn("persist-credentials: false", ci)

    def test_all_external_actions_in_affected_workflows_are_pinned_full_sha(self):
        for name in ("task-branch-publisher.yml", "infrastructure-ci.yml"):
            workflow = (ROOT / ".github" / "workflows" / name).read_text()
            uses = re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", workflow)
            self.assertTrue(uses, name)
            for action, ref in uses:
                with self.subTest(workflow=name, action=action):
                    self.assertRegex(ref, r"^[0-9a-f]{40}$")
                    if action == "actions/checkout":
                        self.assertEqual(ref, CHECKOUT_SHA)
            self.assertNotRegex(workflow, r"uses:\s*[^\s]+@v\d")
