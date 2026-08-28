from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock
from urllib.parse import urlparse

try:
    import graphify_acceptance_runtime.runtime as runtime
except ModuleNotFoundError:
    runtime = None


class RuntimeV2PresenceRED(unittest.TestCase):
    def test_runtime_v2_implementation_is_present(self):
        self.assertIsNotNone(runtime, "runtime-v2 implementation is not published yet")


@unittest.skipIf(runtime is None, "runtime-v2 implementation is intentionally absent at RED")
class RuntimeV2FocusedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="i10-0085-test-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    @staticmethod
    def _regular(name: str, data: bytes = b"x", mode: int = 0o644):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = mode
        return info, data

    @staticmethod
    def _directory(name: str, mode: int = 0o755):
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.mode = mode
        info.size = 0
        return info, None

    @staticmethod
    def _symlink(name: str, linkname: str):
        info = tarfile.TarInfo(name)
        info.type = tarfile.SYMTYPE
        info.mode = 0o777
        info.size = 0
        info.linkname = linkname
        return info, None

    @staticmethod
    def _hardlink(name: str, linkname: str):
        info = tarfile.TarInfo(name)
        info.type = tarfile.LNKTYPE
        info.mode = 0o644
        info.size = 0
        info.linkname = linkname
        return info, None

    def _tar(self, entries):
        path = self.tmp / f"archive-{len(list(self.tmp.glob('archive-*')))}.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for info, data in entries:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    def _mini_archive_and_layout(self):
        entries = [
            self._directory(".", 0o755),
            self._directory("./bin/", 0o755),
            self._regular("./bin/python3.12", b"python", 0o755),
            self._symlink("./bin/python3", "python3.12"),
        ]
        archive = self._tar(entries)
        root = {
            "raw_name": ".", "member_type": "archive_root_sentinel", "tar_type": "5",
            "mode": 0o755, "size": 0, "linkname": "", "normalized_path": None, "extract": False,
        }
        records = [
            {
                "raw_name": "./bin", "normalized_path": "bin", "member_type": "directory",
                "tar_type": "5", "mode": 0o755, "size": 0, "linkname": "", "extract": True,
            },
            {
                "raw_name": "./bin/python3", "normalized_path": "bin/python3", "member_type": "symlink",
                "tar_type": "2", "mode": 0o777, "size": 0, "linkname": "python3.12", "extract": True,
                "normalized_linkname": "python3.12", "resolved_target": "bin/python3.12",
            },
            {
                "raw_name": "./bin/python3.12", "normalized_path": "bin/python3.12", "member_type": "regular",
                "tar_type": "0", "mode": 0o755, "size": 6, "linkname": "", "extract": True,
            },
        ]
        canonical = json.dumps([root, *records], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        allowed_link = dict(records[1])
        allowed_link["terminal_target"] = "bin/python3.12"
        allowed_link["terminal_target_type"] = "regular"
        layout = runtime._ArchiveLayoutContract(
            canonical_inventory_sha256=hashlib.sha256(canonical).hexdigest(),
            canonical_inventory_bytes=len(canonical),
            total_member_count=4,
            archive_root_sentinel_count=1,
            directory_count=1,
            regular_count=1,
            symlink_count=1,
            hardlink_count=0,
            special_count=0,
            root_sentinel=root,
            symlinks=(allowed_link,),
        )
        return archive, layout

    def test_exact_protected_identity_and_runtime_v2_layout_constants(self):
        self.assertEqual(runtime.RELEASE_TAG, "3.12.10-14343898437")
        self.assertEqual(runtime.ARTIFACT_FILENAME, "python-3.12.10-linux-24.04-x64.tar.gz")
        self.assertEqual(runtime.ARTIFACT_BYTES, 121612690)
        self.assertEqual(runtime.ARTIFACT_SHA256, "b9bd943c5fc9244f796deef42c59d29ab9278d8a718851c67de6b44846320f33")
        self.assertEqual(runtime.FINAL_REDIRECT_HOST, "release-assets.githubusercontent.com")
        self.assertEqual(runtime.EXPECTED_REPORT, "CPython 3.12.10")
        self.assertEqual(runtime.SEMANTIC_BUILDER_TIMEOUT_SECONDS, 900)
        self.assertEqual(runtime.EXACT_LAYOUT.canonical_inventory_sha256, "266fbc38be6ffdc9c565953d44cc208e74d6db8a2f038186580fd4904279f3db")
        self.assertEqual(runtime.EXACT_LAYOUT.canonical_inventory_bytes, 2361714)
        self.assertEqual((runtime.EXACT_LAYOUT.total_member_count, runtime.EXACT_LAYOUT.directory_count,
                          runtime.EXACT_LAYOUT.regular_count, runtime.EXACT_LAYOUT.symlink_count,
                          runtime.EXACT_LAYOUT.hardlink_count, runtime.EXACT_LAYOUT.special_count),
                         (9341, 447, 8884, 9, 0, 0))
        self.assertEqual(len(runtime.EXACT_LAYOUT.symlinks), 9)
        self.assertEqual(runtime.EXACT_LAYOUT.symlinks[3]["normalized_path"], "bin/python3")
        self.assertEqual(runtime.EXACT_LAYOUT.symlinks[3]["terminal_target"], "bin/python3.12")
        self.assertFalse(runtime.CREDENTIALS_AUTHORIZED)
        self.assertFalse(runtime.PROTECTED_PATH_MUTATION_AUTHORIZED)
        self.assertEqual(urlparse(runtime.ARTIFACT_URL).hostname, "github.com")

    def test_raw_transport_normalization_allows_only_single_leading_prefix_and_root_sentinel_is_separate(self):
        self.assertEqual(runtime._normalize_member_path("./setup.sh", member_type="regular"), "setup.sh")
        self.assertEqual(runtime._normalize_member_path("setup.sh", member_type="regular"), "setup.sh")
        self.assertEqual(runtime._normalize_member_path("./bin/", member_type="directory"), "bin")
        for raw, kind in [
            ("./", "directory"), ("././x", "regular"), (".//x", "regular"),
            ("foo/./bar", "regular"), ("foo/../bar", "regular"), ("foo//bar", "regular"),
            ("../x", "regular"), ("/x", "regular"), ("C:/x", "regular"),
            ("./C:/x", "regular"), ("foo\\bar", "regular"), ("foo/", "regular"),
            ("foo//", "directory"), (".\x00x", "regular"),
        ]:
            with self.subTest(raw=raw):
                with self.assertRaises(runtime.RuntimeAcquisitionError):
                    runtime._normalize_member_path(raw, member_type=kind)
        for raw in ["", "./", "././x", ".//x", "../x", "./../x", "foo/./bar", "foo/../bar",
                    "foo//bar", "/x", "C:/x", "./C:/x", "foo\\bar"]:
            with self.subTest(linkname=raw):
                with self.assertRaises(runtime.RuntimeAcquisitionError):
                    runtime._normalize_linkname(raw)

    def test_duplicate_canonical_paths_traversal_hardlink_special_dangling_and_cycle_fail_in_pass_zero(self):
        duplicate = self._tar([
            self._directory("."), self._regular("foo"), self._regular("./foo"),
        ])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "duplicate canonical"):
            runtime._scan_inventory(duplicate)

        traversal = self._tar([self._directory("."), self._regular("../escape")])
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            runtime._scan_inventory(traversal)

        hard = self._tar([self._directory("."), self._regular("target"), self._hardlink("hard", "target")])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "hardlink"):
            runtime._scan_inventory(hard, reject_hardlinks=True)

        fifo = tarfile.TarInfo("fifo"); fifo.type = tarfile.FIFOTYPE
        special = self._tar([self._directory("."), (fifo, None)])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "special"):
            runtime._scan_inventory(special, reject_specials=True)

        dangling = self._tar([self._directory("."), self._symlink("link", "missing")])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "dangling"):
            runtime._scan_inventory(dangling)

        cycle = self._tar([self._directory("."), self._symlink("a", "b"), self._symlink("b", "a")])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "cycle"):
            runtime._scan_inventory(cycle)

    def test_complete_pass_zero_precedes_any_output_and_rejects_inventory_drift(self):
        archive, layout = self._mini_archive_and_layout()
        # Same namespace but changed symlink identity => exact canonical digest/link allowlist drift.
        bad = self._tar([
            self._directory(".", 0o755), self._directory("./bin/", 0o755),
            self._regular("./bin/python3.12", b"python", 0o755),
            self._symlink("./bin/python3", "other"),
        ])
        target = self.tmp / "target"
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            runtime._extract_verified_archive(bad, target, layout=layout)
        self.assertFalse(os.path.lexists(target))
        # Control archive does validate under the same mini contract.
        inventory = runtime._validate_exact_inventory(archive, layout=layout)
        self.assertEqual(inventory.canonical_sha256, layout.canonical_inventory_sha256)

    def test_two_pass_extraction_creates_regulars_then_exact_symlink_and_post_verifies_containment(self):
        archive, layout = self._mini_archive_and_layout()
        target = self.tmp / "target"
        inventory = runtime._extract_verified_archive(archive, target, layout=layout)
        self.assertEqual((target / "bin/python3.12").read_bytes(), b"python")
        link = target / "bin/python3"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "python3.12")
        self.assertEqual(link.resolve(strict=True), (target / "bin/python3.12").resolve())
        runtime._verify_extracted_inventory(target, inventory)

        unexpected = target / "unexpected"
        unexpected.write_text("drift")
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "unexpected"):
            runtime._verify_extracted_inventory(target, inventory)

    def test_non_directory_parent_is_rejected_during_pass_zero(self):
        archive = self._tar([
            self._directory("."), self._regular("a", b"file"), self._regular("a/b", b"child")
        ])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "parent"):
            runtime._scan_inventory(archive)

    def test_existing_target_and_overwrite_are_rejected(self):
        archive, layout = self._mini_archive_and_layout()
        target = self.tmp / "target"
        target.mkdir()
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "already exists"):
            runtime._extract_verified_archive(archive, target, layout=layout)

    def test_bounded_setup_times_out_and_cleans_partial_output(self):
        archive, layout = self._mini_archive_and_layout()
        target = self.tmp / "target"
        with mock.patch.object(runtime.time, "monotonic", side_effect=[0.0, 10.0, 10.0, 10.0]):
            with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "timeout"):
                runtime._extract_verified_archive(archive, target, layout=layout, timeout=1)
        self.assertFalse(os.path.lexists(target))

    def test_exact_download_is_anonymous_single_redirect_size_hash_and_fail_closed(self):
        body = b"exact"
        contract = runtime._RuntimeContract(
            url="https://github.com/actions/python-versions/releases/download/tag/python-test.tar.gz",
            filename="python-test.tar.gz", size=len(body), sha256=hashlib.sha256(body).hexdigest(),
            redirect_host=runtime.FINAL_REDIRECT_HOST, executable_report=runtime.EXPECTED_REPORT,
        )

        class Response:
            def __init__(self, status, headers=None, body=b""):
                self.status = status; self.headers = headers or {}; self.body = io.BytesIO(body); self.closed = False
            def getheader(self, name): return self.headers.get(name)
            def read(self, amount=-1): return self.body.read(amount)
            def close(self): self.closed = True

        def get_for(items):
            iterator = iter(items)
            return lambda _url: next(iterator)

        result = runtime._download_archive(
            self.tmp / "ok", contract=contract,
            get=get_for([Response(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/asset"}),
                         Response(200, {"Content-Length": str(len(body))}, body)]),
        )
        self.assertEqual(result, (len(body), contract.sha256, 1, runtime.FINAL_REDIRECT_HOST))

        cases = [
            [Response(200)],
            [Response(302, {"Location": "https://evil.example/asset"})],
            [Response(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/one"}),
             Response(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/two"})],
            [Response(302, {"Location": f"https://{runtime.FINAL_REDIRECT_HOST}/asset"}),
             Response(200, {"Content-Length": "999"}, body)],
        ]
        for index, responses in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(runtime.RuntimeAcquisitionError):
                runtime._download_archive(self.tmp / f"bad-{index}", contract=contract, get=get_for(responses))

    def test_https_get_has_no_credentials_or_cookies(self):
        class FakeRaw:
            status = 200
            def getheader(self, _): return None
            def close(self): pass
        class FakeConnection:
            instances = []
            def __init__(self, host, port=443, timeout=None):
                self.host=host; self.port=port; self.timeout=timeout; self.requests=[]; self.instances.append(self)
            def request(self, method, target, headers=None): self.requests.append((method,target,dict(headers or {})))
            def getresponse(self): return FakeRaw()
            def close(self): pass
        response = runtime._https_get("https://github.com/x", connection_factory=FakeConnection)
        response.close()
        headers = FakeConnection.instances[0].requests[0][2]
        lowered = {key.lower() for key in headers}
        self.assertFalse({"authorization", "cookie", "proxy-authorization"}.intersection(lowered))
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            runtime._https_get("https://user:pass@github.com/x", connection_factory=FakeConnection)

    def test_session_cleanup_report_network_boundary_and_public_surface(self):
        executable = self.tmp / "python3.12"; executable.write_text("x")
        with mock.patch.object(runtime.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="CPython 3.12.9\n")
            with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "report mismatch"):
                runtime._report_python(executable)

        runner_temp = self.tmp / "runner"; runner_temp.mkdir()
        session = runtime.ExactRuntimeSession(runner_temp)
        session.install_root.mkdir(); session.scratch_root.mkdir()
        unrelated = runner_temp / "unrelated"; unrelated.write_text("keep")
        session.cleanup()
        self.assertFalse(os.path.lexists(session.install_root)); self.assertFalse(os.path.lexists(session.scratch_root))
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertEqual(list(inspect.signature(runtime.ExactRuntimeSession).parameters), ["runner_temp"])

        session.python = runner_temp / runtime.INSTALL_DIRNAME / "bin/python3.12"
        session.provenance = runtime.RuntimeProvenance(
            artifact_url=runtime.ARTIFACT_URL, artifact_filename=runtime.ARTIFACT_FILENAME,
            artifact_bytes=runtime.ARTIFACT_BYTES, artifact_sha256=runtime.ARTIFACT_SHA256,
            redirect_count=1, final_host=runtime.FINAL_REDIRECT_HOST, install_root=str(session.install_root),
            executable_report=runtime.EXPECTED_REPORT,
            canonical_inventory_sha256=runtime.EXACT_LAYOUT.canonical_inventory_sha256,
            canonical_inventory_bytes=runtime.EXACT_LAYOUT.canonical_inventory_bytes,
            inventory_counts=runtime.EXACT_LAYOUT.counts,
            symlinks=tuple((item["normalized_path"], item["linkname"], item["terminal_target"]) for item in runtime.EXACT_LAYOUT.symlinks),
            runtime_ready_monotonic=10.0,
        )
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "network must be denied"):
            session.begin_builder_timer()
        executor = session.seal_network()
        with mock.patch.object(runtime.time, "monotonic", return_value=11.0):
            self.assertEqual(session.begin_builder_timer(), 11.0)
        for phase in runtime.PROTECTED_PHASES:
            command = executor.command_for(phase, ["/bin/true"])
            self.assertEqual(command[:3], ["sudo", "--non-interactive", "unshare"])
            self.assertIn("--net", command)
            self.assertIn(f"--reuid={os.getuid()}", command)
            self.assertIn(f"--regid={os.getgid()}", command)
            self.assertIn("--clear-groups", command)
            self.assertIn("--no-new-privs", command)


@unittest.skipUnless(
    os.environ.get("GITHUB_ACTIONS") == "true"
    and runtime is not None
    and Path("evidence/i10-0085/live_acceptance.enabled").is_file(),
    "live GitHub-hosted exact runtime acceptance requires controlled marker",
)
class LiveExactRuntimeV2Acceptance(unittest.TestCase):
    def test_real_pinned_artifact_inventory_symlinks_runtime_network_timer_and_cleanup(self):
        self.assertEqual(os.environ.get("RUNNER_OS"), "Linux")
        self.assertEqual(os.environ.get("RUNNER_ARCH"), "X64")
        forbidden_credentials = {
            "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DATABASE_URL", "PGPASSWORD",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "AZURE_CLIENT_SECRET",
            "GITHUB_APP_PRIVATE_KEY", "DEPLOY_KEY", "SSH_PRIVATE_KEY",
        }
        self.assertFalse(forbidden_credentials.intersection(os.environ))
        self.assertFalse(runtime.CREDENTIALS_AUTHORIZED)
        self.assertFalse(runtime.PROTECTED_PATH_MUTATION_AUTHORIZED)

        runner_temp = Path(os.environ["RUNNER_TEMP"])
        session = runtime.ExactRuntimeSession(runner_temp)
        install_root, scratch_root = session.install_root, session.scratch_root
        evidence = None
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
            self.assertEqual(provenance.canonical_inventory_sha256, runtime.EXACT_LAYOUT.canonical_inventory_sha256)
            self.assertEqual(provenance.canonical_inventory_bytes, runtime.EXACT_LAYOUT.canonical_inventory_bytes)
            self.assertEqual(provenance.inventory_counts, runtime.EXACT_LAYOUT.counts)
            self.assertEqual(len(provenance.symlinks), 9)
            self.assertEqual(provenance.executable_report, "CPython 3.12.10")

            root_resolved = install_root.resolve(strict=True)
            for item in runtime.EXACT_LAYOUT.symlinks:
                link = install_root / item["normalized_path"]
                self.assertTrue(link.is_symlink(), item["normalized_path"])
                self.assertEqual(os.readlink(link), item["normalized_linkname"])
                terminal = link.resolve(strict=True)
                terminal.relative_to(root_resolved)
                self.assertTrue(terminal.is_file())
                self.assertEqual(terminal, (install_root / item["terminal_target"]).resolve(strict=True))

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
            evidence = {
                "artifact_url": provenance.artifact_url,
                "artifact_filename": provenance.artifact_filename,
                "artifact_bytes": provenance.artifact_bytes,
                "artifact_sha256": provenance.artifact_sha256,
                "redirect_count": provenance.redirect_count,
                "final_host": provenance.final_host,
                "canonical_inventory_sha256": provenance.canonical_inventory_sha256,
                "canonical_inventory_bytes": provenance.canonical_inventory_bytes,
                "inventory_counts": provenance.inventory_counts,
                "symlink_count": len(provenance.symlinks),
                "symlinks": [
                    {
                        "path": path,
                        "linkname": linkname,
                        "terminal_target": terminal_target,
                        "terminal_containment_safe_regular": True,
                    }
                    for path, linkname, terminal_target in provenance.symlinks
                ],
                "runtime": provenance.executable_report,
                "network": "denied-before-protected-phases",
                "builder_timer_seconds": runtime.SEMANTIC_BUILDER_TIMEOUT_SECONDS,
                "timer_order": "after-runtime-ready",
                "credentials": "absent",
                "protected_path_authority": "absent",
            }
            print("I10-0085 LIVE RUNTIME V2 ACCEPTANCE " + json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        finally:
            session.cleanup()
        self.assertIsNotNone(evidence)
        self.assertFalse(os.path.lexists(install_root))
        self.assertFalse(os.path.lexists(scratch_root))
        print("I10-0085 LIVE CLEANUP verified=true")


if __name__ == "__main__":
    unittest.main()
