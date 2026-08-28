from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

import graphify_acceptance_runtime.runtime as runtime


class RuntimeV2CompressedExtractionOrderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="i10-0085-order-"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    @staticmethod
    def _directory(name: str):
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.mode = 0o755
        info.size = 0
        return info, None

    @staticmethod
    def _regular(name: str, data: bytes):
        info = tarfile.TarInfo(name)
        info.mode = 0o644
        info.size = len(data)
        return info, data

    def test_regular_payloads_follow_archive_member_order(self):
        archive_path = self.tmp / "order.tar.gz"
        entries = [
            self._directory("."),
            self._directory("./bin/"),
            self._regular("./bin/z-last-lexically", b"z"),
            self._regular("./bin/a-first-lexically", b"a"),
        ]
        with tarfile.open(archive_path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            for info, data in entries:
                archive.addfile(info, io.BytesIO(data) if data is not None else None)

        inventory = runtime._scan_inventory(
            archive_path,
            reject_hardlinks=True,
            reject_specials=True,
        )
        layout = runtime._ArchiveLayoutContract(
            canonical_inventory_sha256=inventory.canonical_sha256,
            canonical_inventory_bytes=inventory.canonical_bytes,
            total_member_count=inventory.counts["total_member_count"],
            archive_root_sentinel_count=inventory.counts["archive_root_sentinel_count"],
            directory_count=inventory.counts["directory_count"],
            regular_count=inventory.counts["regular_count"],
            symlink_count=inventory.counts["symlink_count"],
            hardlink_count=inventory.counts["hardlink_count"],
            special_count=inventory.counts["special_count"],
            root_sentinel=inventory.root_sentinel,
            symlinks=inventory.symlinks,
        )

        seen: list[str] = []
        original_extractfile = tarfile.TarFile.extractfile

        def recording_extractfile(tar: tarfile.TarFile, member):
            seen.append(member.name)
            return original_extractfile(tar, member)

        target = self.tmp / "target"
        with mock.patch.object(tarfile.TarFile, "extractfile", new=recording_extractfile):
            runtime._extract_verified_archive(archive_path, target, layout=layout)

        self.assertEqual(
            seen,
            ["./bin/z-last-lexically", "./bin/a-first-lexically"],
            "compressed payload extraction must preserve archive member order to avoid backward gzip seeks",
        )
        self.assertEqual((target / "bin/z-last-lexically").read_bytes(), b"z")
        self.assertEqual((target / "bin/a-first-lexically").read_bytes(), b"a")
        self.assertFalse(os.path.islink(target / "bin"))


if __name__ == "__main__":
    unittest.main()
