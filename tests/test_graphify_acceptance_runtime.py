from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlparse

import graphify_acceptance_runtime.runtime as runtime


class FakeResponse:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self.body = io.BytesIO(body)
        self.closed = False

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, amount=-1):
        return self.body.read(amount)

    def close(self):
        self.closed = True


class FakeConnection:
    instances = []
    responses = []

    def __init__(self, host, port=443, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.requests = []
        self.response = self.responses.pop(0)
        self.instances.append(self)

    def request(self, method, target, headers=None):
        self.requests.append((method, target, dict(headers or {})))

    def getresponse(self):
        return self.response

    def close(self):
        pass


class ExactRuntimeContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        FakeConnection.instances = []
        FakeConnection.responses = []

    @staticmethod
    def mini_contract(body=b"exact"):
        return runtime._RuntimeContract(
            url="https://github.com/actions/python-versions/releases/download/tag/python-test.tar.gz",
            filename="python-test.tar.gz",
            size=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            redirect_host=runtime.FINAL_REDIRECT_HOST,
            executable_report=runtime.EXPECTED_REPORT,
        )

    def get_for(self, responses):
        it = iter(responses)
        return lambda url: next(it)

    def test_exact_protected_identity_constants(self):
        self.assertEqual(runtime.RELEASE_TAG, "3.12.10-14343898437")
        self.assertEqual(runtime.ARTIFACT_FILENAME, "python-3.12.10-linux-24.04-x64.tar.gz")
        self.assertEqual(runtime.ARTIFACT_BYTES, 121612690)
        self.assertEqual(runtime.ARTIFACT_SHA256, "b9bd943c5fc9244f796deef42c59d29ab9278d8a718851c67de6b44846320f33")
        self.assertEqual(runtime.FINAL_REDIRECT_HOST, "release-assets.githubusercontent.com")
        self.assertEqual(runtime.EXPECTED_REPORT, "CPython 3.12.10")
        self.assertEqual(urlparse(runtime.ARTIFACT_URL).hostname, "github.com")
        self.assertEqual(Path(urlparse(runtime.ARTIFACT_URL).path).name, runtime.ARTIFACT_FILENAME)

    def test_https_get_sends_no_authorization_or_cookies(self):
        FakeConnection.responses = [FakeResponse(200)]
        response = runtime._https_get("https://github.com/x", connection_factory=FakeConnection)
        response.close()
        headers = FakeConnection.instances[0].requests[0][2]
        lowered = {key.lower() for key in headers}
        self.assertNotIn("authorization", lowered)
        self.assertNotIn("cookie", lowered)
        self.assertNotIn("proxy-authorization", lowered)
        self.assertEqual(FakeConnection.instances[0].timeout, runtime.DOWNLOAD_TIMEOUT_SECONDS)

    def test_download_accepts_exact_single_redirect_size_and_hash(self):
        body = b"exact"
        contract = self.mini_contract(body)
        responses = [
            FakeResponse(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/asset"}),
            FakeResponse(200, {"Content-Length": str(len(body))}, body),
        ]
        result = runtime._download_archive(self.tmp / "x", contract=contract, get=self.get_for(responses))
        self.assertEqual(result, (len(body), contract.sha256, 1, runtime.FINAL_REDIRECT_HOST))

    def test_bad_redirect_and_unexpected_host_are_rejected(self):
        contract = self.mini_contract()
        cases = [
            [FakeResponse(200)],
            [FakeResponse(302, {"Location": "https://evil.example/asset"})],
        ]
        for index, responses in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(runtime.RuntimeAcquisitionError):
                    runtime._download_archive(self.tmp / f"x{index}", contract=contract, get=self.get_for(responses))

    def test_second_redirect_is_rejected(self):
        contract = self.mini_contract()
        responses = [
            FakeResponse(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/one"}),
            FakeResponse(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/two"}),
        ]
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "exceeded one redirect"):
            runtime._download_archive(self.tmp / "x", contract=contract, get=self.get_for(responses))

    def test_short_long_and_hash_mismatch_are_rejected_and_partial_removed(self):
        exact = b"exact"
        contract = self.mini_contract(exact)
        cases = [
            (b"exa", str(len(exact)), "byte count"),
            (b"exact!", str(len(exact)), "exceeds"),
            (b"other", str(len(exact)), "SHA-256"),
        ]
        for index, (body, declared, message) in enumerate(cases):
            destination = self.tmp / f"x{index}"
            responses = [
                FakeResponse(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/asset"}),
                FakeResponse(200, {"Content-Length": declared}, body),
            ]
            with self.subTest(index=index), self.assertRaisesRegex(runtime.RuntimeAcquisitionError, message):
                runtime._download_archive(destination, contract=contract, get=self.get_for(responses))
            self.assertFalse(destination.exists())

    def test_content_length_mismatch_is_rejected_before_body_use(self):
        contract = self.mini_contract()
        responses = [
            FakeResponse(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/asset"}),
            FakeResponse(200, {"Content-Length": "999"}, b"exact"),
        ]
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "Content-Length"):
            runtime._download_archive(self.tmp / "x", contract=contract, get=self.get_for(responses))

    def make_tar(self, entries):
        path = self.tmp / f"archive-{len(list(self.tmp.glob('archive-*')))}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for info, data in entries:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    def regular(self, name, data=b"x", mode=0o755):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        return info, data

    def test_safe_extraction_rejects_traversal_absolute_symlink_hardlink_and_special(self):
        malicious = []
        malicious.append(self.regular("../escape"))
        malicious.append(self.regular("/absolute"))
        symlink = tarfile.TarInfo("link"); symlink.type = tarfile.SYMTYPE; symlink.linkname = "target"; malicious.append((symlink, None))
        hardlink = tarfile.TarInfo("hard"); hardlink.type = tarfile.LNKTYPE; hardlink.linkname = "../escape"; malicious.append((hardlink, None))
        fifo = tarfile.TarInfo("fifo"); fifo.type = tarfile.FIFOTYPE; malicious.append((fifo, None))
        char = tarfile.TarInfo("char"); char.type = tarfile.CHRTYPE; malicious.append((char, None))
        for index, entry in enumerate(malicious):
            archive = self.make_tar([entry])
            target = self.tmp / f"target-{index}"
            with self.subTest(index=index), self.assertRaises(runtime.RuntimeAcquisitionError):
                runtime._extract_verified_archive(archive, target)
            self.assertFalse(target.exists())

    def test_archive_is_fully_validated_before_any_target_is_created(self):
        archive = self.make_tar([self.regular("safe/file"), self.regular("../escape")])
        target = self.tmp / "target"
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            runtime._extract_verified_archive(archive, target)
        self.assertFalse(target.exists())

    def test_safe_extraction_rejects_preexisting_target_and_duplicate_members(self):
        archive = self.make_tar([self.regular("bin/python3.12")])
        target = self.tmp / "target"
        target.mkdir()
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "already exists"):
            runtime._extract_verified_archive(archive, target)

        one = tarfile.TarInfo("dup"); one.size = 1
        two = tarfile.TarInfo("dup"); two.size = 1
        duplicate = self.make_tar([(one, b"a"), (two, b"b")])
        duplicate_target = self.tmp / "duplicate"
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "duplicate"):
            runtime._extract_verified_archive(duplicate, duplicate_target)

    def test_bounded_setup_fails_closed(self):
        archive = self.make_tar([self.regular("bin/python3.12")])
        with mock.patch.object(runtime.time, "monotonic", side_effect=[0, 10, 10]):
            with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "timeout"):
                runtime._extract_verified_archive(archive, self.tmp / "target", timeout=1)

    def test_exact_python_report_is_required(self):
        executable = self.tmp / "python3.12"
        executable.write_text("x")
        with mock.patch.object(runtime.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="CPython 3.12.9\n")
            with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "report mismatch"):
                runtime._report_python(executable)
            self.assertEqual(run.call_args.kwargs["timeout"], runtime.VERSION_TIMEOUT_SECONDS)

    def test_prepare_failure_cleans_task_local_material(self):
        runner_temp = self.tmp / "runner"; runner_temp.mkdir()
        session = runtime.ExactRuntimeSession(runner_temp)
        with mock.patch.object(runtime, "_download_archive", side_effect=runtime.RuntimeAcquisitionError("boom")):
            with self.assertRaises(runtime.RuntimeAcquisitionError):
                session.prepare()
        self.assertFalse(session.install_root.exists())
        self.assertFalse(session.scratch_root.exists())

    def test_session_rejects_preexisting_task_local_and_scratch_locations(self):
        runner_temp = self.tmp / "runner"; runner_temp.mkdir()
        (runner_temp / runtime.INSTALL_DIRNAME).mkdir()
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "target already exists"):
            runtime.ExactRuntimeSession(runner_temp)._assert_fresh_locations()
        shutil.rmtree(runner_temp / runtime.INSTALL_DIRNAME)
        (runner_temp / runtime.SCRATCH_DIRNAME).mkdir()
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "scratch/cache"):
            runtime.ExactRuntimeSession(runner_temp)._assert_fresh_locations()

    def test_network_shutdown_precedes_timer_and_protected_phases_are_fail_closed(self):
        runner_temp = self.tmp / "runner"; runner_temp.mkdir()
        session = runtime.ExactRuntimeSession(runner_temp)
        session.python = runner_temp / runtime.INSTALL_DIRNAME / "bin/python3.12"
        session.provenance = runtime.RuntimeProvenance(
            runtime.ARTIFACT_URL, runtime.ARTIFACT_FILENAME, runtime.ARTIFACT_BYTES,
            runtime.ARTIFACT_SHA256, 1, runtime.FINAL_REDIRECT_HOST,
            str(session.install_root), runtime.EXPECTED_REPORT, 10.0,
        )
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "network must be denied"):
            session.begin_builder_timer()
        executor = session.seal_network()
        with mock.patch.object(runtime.time, "monotonic", return_value=11.0):
            self.assertEqual(session.begin_builder_timer(), 11.0)
        for phase in runtime.PROTECTED_PHASES:
            command = executor.command_for(phase, ["/bin/true"])
            self.assertIn("--net", command)
            self.assertEqual(command[0:3], ["sudo", "--non-interactive", "unshare"])
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            executor.command_for("runtime_acquisition", ["/bin/true"])
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            session.seal_network()

    def test_public_session_has_no_runtime_substitution_or_cache_parameters(self):
        import inspect
        signature = inspect.signature(runtime.ExactRuntimeSession)
        self.assertEqual(list(signature.parameters), ["runner_temp"])
        source = Path(runtime.__file__).read_text()
        for forbidden in (
            "actions/setup-python", "RUNNER_TOOL_CACHE", "version-manifest", "latest", "mirror",
            "GITHUB_TOKEN", "Authorization\"", "Cookie\"",
        ):
            self.assertNotIn(forbidden, source)

    def test_cleanup_removes_only_task_local_material(self):
        runner_temp = self.tmp / "runner"; runner_temp.mkdir()
        unrelated = runner_temp / "unrelated"; unrelated.write_text("keep")
        session = runtime.ExactRuntimeSession(runner_temp)
        session.install_root.mkdir()
        session.scratch_root.mkdir()
        session.cleanup()
        self.assertFalse(session.install_root.exists())
        self.assertFalse(session.scratch_root.exists())
        self.assertEqual(unrelated.read_text(), "keep")


@unittest.skipUnless(os.environ.get("GITHUB_ACTIONS") == "true", "live GitHub-hosted runner acceptance")
class LiveExactRuntimeAcceptanceTests(unittest.TestCase):
    def test_real_exact_runtime_acquisition_network_shutdown_timer_and_cleanup(self):
        self.assertEqual(os.environ.get("RUNNER_OS"), "Linux")
        self.assertEqual(os.environ.get("RUNNER_ARCH"), "X64")
        runner_temp = Path(os.environ["RUNNER_TEMP"])
        forbidden_credentials = {
            "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
            "DATABASE_URL", "PGPASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
        }
        self.assertFalse(forbidden_credentials.intersection(os.environ))

        session = runtime.ExactRuntimeSession(runner_temp)
        install_root = session.install_root
        scratch_root = session.scratch_root
        try:
            session.prepare()
            provenance = session.provenance
            self.assertIsNotNone(provenance)
            self.assertEqual(provenance.artifact_url, runtime.ARTIFACT_URL)
            self.assertEqual(provenance.artifact_filename, runtime.ARTIFACT_FILENAME)
            self.assertEqual(provenance.artifact_bytes, runtime.ARTIFACT_BYTES)
            self.assertEqual(provenance.artifact_sha256, runtime.ARTIFACT_SHA256)
            self.assertEqual(provenance.redirect_count, 1)
            self.assertEqual(provenance.final_host, runtime.FINAL_REDIRECT_HOST)
            self.assertEqual(provenance.executable_report, runtime.EXPECTED_REPORT)
            self.assertEqual(Path(provenance.install_root), runner_temp / "task-local")

            executor = session.seal_network()
            timer_started = session.begin_builder_timer()
            self.assertGreaterEqual(timer_started, provenance.runtime_ready_monotonic)
            script = (
                "import socket,sys; "
                "\ntry: socket.create_connection(('github.com',443),2); sys.exit(9)"
                "\nexcept OSError: print('NETWORK_DENIED')"
            )
            witness = executor.run("artifact_setup", [str(session.python), "-c", script], timeout=20)
            self.assertEqual(witness.stdout.strip(), "NETWORK_DENIED")
            print(
                "I10-0085 LIVE ACCEPTANCE",
                f"runner={os.environ.get('RUNNER_NAME','unknown')}",
                f"url={provenance.artifact_url}",
                f"bytes={provenance.artifact_bytes}",
                f"sha256={provenance.artifact_sha256}",
                f"redirects={provenance.redirect_count}",
                f"final_host={provenance.final_host}",
                f"runtime={provenance.executable_report}",
                f"install_root={provenance.install_root}",
                "network=denied-before-protected-phases",
                "timer=after-runtime-ready",
            )
        finally:
            session.cleanup()
        self.assertFalse(install_root.exists())
        self.assertFalse(scratch_root.exists())


if __name__ == "__main__":
    unittest.main()
