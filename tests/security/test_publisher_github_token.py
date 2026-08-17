import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from security.publisher_test_support import *  # noqa: F401,F403
from publisher_backend import GIT_REMOTE, GitHubAPIBackend
from publisher_runtime_backend import PublisherRuntimeBackend


class PublisherGitHubTokenSecurity(unittest.TestCase):
    def test_https_lease_uses_temporary_askpass_without_token_in_git_process_or_config(self):
        token = "ghs_test_token_that_must_never_be_process_visible"
        backend = GitHubAPIBackend(token=token, repository="Dsamofalov/hwm-lab", repo_root=ROOT)
        observed = {}

        def fake_run(args, **kwargs):
            env = kwargs["env"]
            observed["args"] = list(args)
            observed["token_path"] = env["HWM_PUBLISHER_ASKPASS_TOKEN_FILE"]
            observed["askpass_path"] = env["GIT_ASKPASS"]
            self.assertFalse(any(token in str(value) for value in args))
            self.assertFalse(any(token in str(value) for value in env.values()))
            self.assertEqual(args[0], "git")
            self.assertIn("credential.helper=", args)
            self.assertIn(
                f"--force-with-lease=refs/heads/agent/infra-0013-token-test:{BASE}",
                args,
            )
            self.assertIn(GIT_REMOTE, args)
            self.assertNotIn("@github.com", GIT_REMOTE)
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            token_path = Path(observed["token_path"])
            askpass_path = Path(observed["askpass_path"])
            self.assertEqual(token_path.read_text(encoding="utf-8"), token)
            self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(askpass_path.stat().st_mode), 0o700)
            self.assertNotIn(token, askpass_path.read_text(encoding="utf-8"))
            return SimpleNamespace(returncode=0)

        with mock.patch.dict(
            os.environ,
            {"HWM_PUBLISHER_TOKEN": token, "GITHUB_TOKEN": token, "GH_TOKEN": token},
            clear=False,
        ):
            with mock.patch("publisher_backend.subprocess.run", side_effect=fake_run):
                self.assertTrue(
                    backend.compare_and_set_branch(
                        "agent/infra-0013-token-test", BASE, NEW
                    )
                )

        self.assertFalse(Path(observed["token_path"]).exists())
        self.assertFalse(Path(observed["askpass_path"]).exists())

    def test_runtime_uses_accepted_git_cas_for_immediate_post_push_head_read(self):
        branch = "agent/infra-0013-token-test"
        backend = PublisherRuntimeBackend(
            token="test-token", repository="Dsamofalov/hwm-lab", repo_root=ROOT
        )
        with mock.patch.object(
            GitHubAPIBackend, "compare_and_set_branch", return_value=True
        ) as cas, mock.patch.object(
            GitHubAPIBackend, "get_branch_head", return_value=BASE
        ) as stale_rest:
            self.assertTrue(backend.compare_and_set_branch(branch, BASE, NEW))
            cas.assert_called_once_with(branch, BASE, NEW)
            self.assertEqual(backend.get_branch_head(branch), NEW)
            stale_rest.assert_not_called()
            self.assertEqual(backend.get_branch_head(branch), BASE)
            stale_rest.assert_called_once_with(branch)

    def test_failed_git_cas_never_masks_actual_remote_head(self):
        branch = "agent/infra-0013-token-test"
        backend = PublisherRuntimeBackend(
            token="test-token", repository="Dsamofalov/hwm-lab", repo_root=ROOT
        )
        with mock.patch.object(
            GitHubAPIBackend, "compare_and_set_branch", return_value=False
        ), mock.patch.object(
            GitHubAPIBackend, "get_branch_head", return_value=RACE
        ) as remote:
            self.assertFalse(backend.compare_and_set_branch(branch, BASE, NEW))
            self.assertEqual(backend.get_branch_head(branch), RACE)
            remote.assert_called_once_with(branch)

    def test_runner_entrypoint_removes_job_token_before_git_subprocesses(self):
        source = (ROOT / "control" / "run_task_branch_publisher.py").read_text()
        self.assertIn('os.environ.pop("HWM_PUBLISHER_TOKEN", None)', source)
        self.assertIn("PublisherRuntimeBackend", source)
        self.assertNotIn("HWM_PUBLISHER_DEPLOY_KEY", source)
        self.assertNotIn("known_hosts", source)
        self.assertNotIn("ssh -i", source)

    def test_backend_has_no_tokenized_remote_or_persistent_credential_write(self):
        source = (ROOT / "control" / "publisher_backend.py").read_text()
        self.assertIn('GIT_REMOTE = "https://github.com/Dsamofalov/hwm-lab.git"', source)
        self.assertNotIn("git@github.com", source)
        self.assertNotIn("remote set-url", source)
        self.assertNotIn("credential.helper store", source)
        self.assertNotIn("credential.helper cache", source)
        self.assertIn("GIT_ASKPASS", source)
        self.assertIn("TemporaryDirectory", source)
