from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import graphify_acceptance_runtime.runtime as runtime


class RuntimeV2TaskLocalBindingTest(unittest.TestCase):
    def test_runtime_report_binds_exact_task_local_library_and_python_home(self):
        install_root = Path(tempfile.mkdtemp(prefix="i10-0085-binding-")) / "task-local"
        python = install_root / "bin" / "python3.12"
        with mock.patch.object(runtime.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout=runtime.EXPECTED_REPORT + "\n")
            self.assertEqual(runtime._report_python(python), runtime.EXPECTED_REPORT)
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["LD_LIBRARY_PATH"], str(install_root / "lib"))
        self.assertEqual(env["PYTHONHOME"], str(install_root))
        self.assertEqual(env["PYTHONNOUSERSITE"], "1")

    def test_network_denied_executor_sets_binding_after_privilege_drop(self):
        install_root = Path("/runner-temp/task-local")
        executor = runtime.NetworkDeniedExecutor(install_root)
        command = executor.command_for("artifact_setup", [str(install_root / "bin/python3.12"), "-V"])
        separator = command.index("--", command.index("--no-new-privs") + 1)
        bound = command[separator + 1:]
        self.assertEqual(bound[0], "/usr/bin/env")
        self.assertIn(f"LD_LIBRARY_PATH={install_root / 'lib'}", bound)
        self.assertIn(f"PYTHONHOME={install_root}", bound)
        self.assertIn("PYTHONNOUSERSITE=1", bound)
        self.assertEqual(bound[-2:], [str(install_root / "bin/python3.12"), "-V"])
        self.assertNotIn("RUNNER_TOOL_CACHE", " ".join(command))
        self.assertNotIn("AGENT_TOOLSDIRECTORY", " ".join(command))


if __name__ == "__main__":
    unittest.main()
