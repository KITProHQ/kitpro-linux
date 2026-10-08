from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tools import check_tracked_secrets, kitpro_phase2, kitpro_repo


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT / "repo"
STATE = ROOT / ".state"
ARTIFACTS = STATE / "phase2/artifacts"
RELEASE = "0.1-dev"
G1 = "0.1-dev-g0001"
G2 = "0.1-dev-g0002"
G4 = "0.1-dev-g0004"


@unittest.skipUnless(
    os.environ.get("KITPRO_PHASE2_ACCEPTANCE") == "1",
    "set KITPRO_PHASE2_ACCEPTANCE=1 after running the Phase 2 QEMU suite",
)
class Phase2AcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.g1_root = REPO / "stable" / RELEASE / G1
        cls.g2_root = REPO / "stable" / RELEASE / G2
        cls.g1 = json.loads((cls.g1_root / "manifest.json").read_text())
        cls.g2 = json.loads((cls.g2_root / "manifest.json").read_text())
        cls.keys = STATE / "dev-keys"
        cls.rootfs_manifest = json.loads((ARTIFACTS / "rootfs-manifest.json").read_text())
        cls.acceptance = json.loads((ARTIFACTS / "phase2-acceptance.json").read_text())

    def test_both_stable_generations_validate(self) -> None:
        for manifest, root in ((self.g1, self.g1_root), (self.g2, self.g2_root)):
            kitpro_repo.validate_manifest(manifest)
            kitpro_repo.verify_manifest_artifacts(manifest, REPO, root, self.keys)

    def test_update_changes_only_release_package(self) -> None:
        before = {package["name"]: package for package in self.g1["repositories"][0]["packages"]}
        after = {package["name"]: package for package in self.g2["repositories"][0]["packages"]}
        changed = [name for name in before if before[name]["sha256"] != after[name]["sha256"]]
        self.assertEqual(changed, ["kitpro-linux-release"])
        self.assertEqual(before["kitpro-linux-release"]["version"], "0.1.0-1")
        self.assertEqual(after["kitpro-linux-release"]["version"], "0.1.0-2")

    def test_update_promotion_preserves_artifacts(self) -> None:
        roots = [REPO / "candidates" / G2 / channel for channel in ("edge", "testing")]
        manifests = [json.loads((root / "manifest.json").read_text()) for root in roots]
        hashes = [kitpro_repo.manifest_artifact_hash(manifest) for manifest in [*manifests, self.g2]]
        self.assertEqual(len(set(hashes)), 1)

    def test_g0002_is_immutable_and_current_targets_qualified_generation(self) -> None:
        self.assertEqual(os.readlink(REPO / "stable" / RELEASE / "current"), G4)
        for path in [self.g2_root, *self.g2_root.rglob("*")]:
            if path.is_symlink():
                continue
            self.assertEqual(
                path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH), 0, str(path)
            )

    def test_rootfs_manifest_and_final_image_validate(self) -> None:
        kitpro_phase2.validate_rootfs_manifest(self.rootfs_manifest)
        image = ROOT / self.rootfs_manifest["disk_image"]["path"]
        self.assertEqual(kitpro_repo.sha256_file(image), self.rootfs_manifest["disk_image"]["sha256"])
        self.assertEqual(self.rootfs_manifest["resolved_package_count"], 167)

    def test_qemu_acceptance_passed(self) -> None:
        self.assertEqual(self.acceptance["result"], "passed")
        self.assertTrue(all(self.acceptance["serial_checks"].values()))
        self.assertTrue(all(check["passed"] for check in self.acceptance["checks"].values()))

    def test_rootfs_inventory_matches_g0001(self) -> None:
        expected = {
            (package["name"], package["version"], package["sha256"])
            for package in self.g1["repositories"][0]["packages"]
        }
        actual = {
            (package["name"], package["version"], package["sha256"])
            for package in self.rootfs_manifest["packages"]
        }
        self.assertEqual(actual, expected)

    def test_missing_and_invalid_repository_signatures_fail(self) -> None:
        database = self.g2["repositories"][0]["database"]
        repository = self.g2_root / "core/os/x86_64"
        with self.assertRaises(kitpro_repo.PipelineError):
            kitpro_repo.verify_signature(
                self.keys / "repository", repository / "missing.db.sig", repository / database["filename"]
            )
        with tempfile.TemporaryDirectory() as name:
            invalid = Path(name) / "invalid.db.sig"
            data = bytearray((repository / database["signature_filename"]).read_bytes())
            data[len(data) // 2] ^= 1
            invalid.write_bytes(data)
            with self.assertRaises(kitpro_repo.PipelineError):
                kitpro_repo.verify_signature(
                    self.keys / "repository", invalid, repository / database["filename"]
                )

    def test_invalid_package_signature_fails(self) -> None:
        package = next(
            package
            for package in self.g2["repositories"][0]["packages"]
            if package["name"] == "kitpro-linux-release"
        )
        repository = self.g2_root / "core/os/x86_64"
        with tempfile.TemporaryDirectory() as name:
            invalid = Path(name) / "invalid.pkg.sig"
            data = bytearray((repository / package["kitpro_signature"]["filename"]).read_bytes())
            data[len(data) // 2] ^= 1
            invalid.write_bytes(data)
            with self.assertRaises(kitpro_repo.PipelineError):
                kitpro_repo.verify_signature(
                    self.keys / "package", invalid, repository / package["filename"]
                )

    def test_pristine_guest_has_no_repository_fallback(self) -> None:
        repositories = kitpro_phase2.validate_repository_isolation(
            STATE / "phase2/rootfs/etc/pacman.conf"
        )
        self.assertEqual(repositories, ["kitpro-0.1-dev-core"])

    def test_no_private_test_or_signing_key_is_tracked(self) -> None:
        self.assertEqual(check_tracked_secrets.violations(check_tracked_secrets.tracked_paths()), [])


if __name__ == "__main__":
    unittest.main()
