from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install.disk import (
    DiskState,
    create_test_disk,
    discover_disk,
    marker_path,
    protected_top_level_devices,
    require_erase_authorization,
)
from tools.install.model import ABSOLUTE_MINIMUM_BYTES


class DiskSafetyTests(unittest.TestCase):
    def test_nonexistent_target_fails(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "does not exist"):
            discover_disk(Path("/tmp/does-not-exist-kitpro-phase3.raw"), "image", ABSOLUTE_MINIMUM_BYTES)

    def test_image_requires_exact_marker(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            with target.open("wb") as handle:
                handle.truncate(ABSOLUTE_MINIMUM_BYTES)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "marker"):
                discover_disk(target, "image", ABSOLUTE_MINIMUM_BYTES)

    def test_test_disk_creation_and_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            state = discover_disk(target, "image", ABSOLUTE_MINIMUM_BYTES)
            self.assertEqual(state.size_bytes, ABSOLUTE_MINIMUM_BYTES)
            self.assertEqual(state.partition_table, "unknown")
            self.assertEqual(state.signatures, ())
            self.assertTrue(marker_path(target).is_file())

    def test_existing_test_disk_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "refusing to replace"):
                create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)

    def test_small_target_fails_before_partitioning(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            marker = create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            os.truncate(target, ABSOLUTE_MINIMUM_BYTES - 1)
            marker["size_bytes"] -= 1
            kitpro_repo.atomic_write_json(marker_path(target), marker)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "too small"):
                discover_disk(target, "image", ABSOLUTE_MINIMUM_BYTES)

    def test_mounted_target_fails_before_partitioning(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "mounted.raw"
            target.touch()
            state = DiskState(
                path=str(target), target_type="image", size_bytes=ABSOLUTE_MINIMUM_BYTES,
                identity={}, mounted_paths=("/mnt/test",), signatures=(),
                partition_table="unknown", marker_sha256="a" * 64,
            )
            with mock.patch("tools.install.disk._discover_image", return_value=state):
                with self.assertRaisesRegex(kitpro_repo.PipelineError, "mounted"):
                    discover_disk(target, "image", ABSOLUTE_MINIMUM_BYTES)

    def test_erase_flag_is_always_required(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "--allow-disk-erase"):
            require_erase_authorization(False)
        require_erase_authorization(True)

    def test_host_and_repository_backing_disks_are_protected(self) -> None:
        protected = protected_top_level_devices()
        if not protected:
            self.skipTest("host and repository filesystems are not backed by visible block devices")
        self.assertIn("host root", protected)
        self.assertIn("development repository", protected)
        self.assertTrue(protected["host root"].startswith("/dev/"))
        self.assertTrue(protected["development repository"].startswith("/dev/"))
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "host root disk"):
            discover_disk(Path(protected["host root"]), "block", ABSOLUTE_MINIMUM_BYTES)


if __name__ == "__main__":
    unittest.main()
