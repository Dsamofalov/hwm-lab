from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

try:
    import graphify_acceptance_runtime.runtime as runtime
except ModuleNotFoundError:
    runtime = None


class RuntimeV2PresenceRED(unittest.TestCase):
    def test_runtime_v2_implementation_is_present(self):
        self.assertIsNotNone(runtime, "runtime-v2 implementation is not published yet")


@unittest.skipIf(runtime is None, "runtime-v2 implementation is intentionally absent at RED")
class RuntimeV2FocusedNegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="i10-0085-red-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    @staticmethod
    def _regular(name: str, data: bytes = b"x"):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o644
        return info, data

    @staticmethod
    def _directory(name: str):
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
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

    def _tar(self, entries):
        path = self.tmp / f"archive-{len(list(self.tmp.glob('archive-*')))}.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for info, data in entries:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
        return path

    def test_exact_runtime_v2_inventory_identity_is_pinned(self):
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

    def test_transport_prefix_and_dot_segment_rules_are_closed(self):
        self.assertEqual(runtime._normalize_member_path("./setup.sh", member_type="regular"), "setup.sh")
        self.assertEqual(runtime._normalize_member_path("./bin/", member_type="directory"), "bin")
        for raw, kind in [("./", "directory"), ("././x", "regular"), (".//x", "regular"),
                          ("foo/./bar", "regular"), ("foo/../bar", "regular"),
                          ("../x", "regular"), ("/x", "regular"), ("C:/x", "regular"),
                          ("./C:/x", "regular"), ("foo\\bar", "regular")]:
            with self.subTest(raw=raw), self.assertRaises(runtime.RuntimeAcquisitionError):
                runtime._normalize_member_path(raw, member_type=kind)
        for raw in ["", "./", "././x", "../x", "./../x", "foo/./bar", "foo/../bar",
                    "foo//bar", "/x", "C:/x", "./C:/x", "foo\\bar"]:
            with self.subTest(linkname=raw), self.assertRaises(runtime.RuntimeAcquisitionError):
                runtime._normalize_linkname(raw)

    def test_pass_zero_rejects_duplicate_traversal_hardlink_special_dangling_and_cycle(self):
        duplicate = self._tar([self._directory("."), self._regular("foo"), self._regular("./foo")])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "duplicate canonical"):
            runtime._scan_inventory(duplicate)
        traversal = self._tar([self._directory("."), self._regular("../escape")])
        with self.assertRaises(runtime.RuntimeAcquisitionError):
            runtime._scan_inventory(traversal)
        hard = tarfile.TarInfo("hard"); hard.type = tarfile.LNKTYPE; hard.linkname = "target"
        hard_archive = self._tar([self._directory("."), self._regular("target"), (hard, None)])
        with self.assertRaisesRegex(runtime.RuntimeAcquisitionError, "hardlink"):
            runtime._scan_inventory(hard_archive, reject_hardlinks=True)
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


@unittest.skipUnless(os.environ.get("GITHUB_ACTIONS") == "true" and runtime is not None,
                     "live acceptance starts only after runtime-v2 implementation")
class LiveRuntimeV2Gate(unittest.TestCase):
    def test_live_gate_is_reserved_for_green_head(self):
        self.fail("GREEN head must replace this RED-only live gate with exact pinned-artifact acceptance")


if __name__ == "__main__":
    unittest.main()
