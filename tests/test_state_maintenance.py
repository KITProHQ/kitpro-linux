from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock

from tools import kitpro_repo, state_maintenance


class StateMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kitpro-state-test-")
        self.project_root = Path(self.temporary.name) / "project"
        self.state_root = self.project_root / ".state"
        self.state_root.mkdir(parents=True)
        self.project_patch = mock.patch.object(
            state_maintenance, "PROJECT_ROOT", self.project_root
        )
        self.state_patch = mock.patch.object(
            state_maintenance, "STATE_ROOT", self.state_root
        )
        self.project_patch.start()
        self.state_patch.start()

    def tearDown(self) -> None:
        self.state_patch.stop()
        self.project_patch.stop()
        self.temporary.cleanup()

    def test_capacity_has_hard_and_recommended_thresholds(self) -> None:
        usage = mock.Mock(total=200 * state_maintenance.GIB, used=100, free=80 * state_maintenance.GIB)
        with mock.patch.object(state_maintenance.shutil, "disk_usage", return_value=usage):
            report = state_maintenance.capacity_report(Path("/tmp"))
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["hard_minimum_bytes"], 75 * state_maintenance.GIB)
        self.assertEqual(report["recommended_bytes"], 150 * state_maintenance.GIB)

    def test_hard_capacity_failure_is_clear(self) -> None:
        usage = mock.Mock(total=200, used=150, free=50 * state_maintenance.GIB)
        with mock.patch.object(state_maintenance.shutil, "disk_usage", return_value=usage):
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "hard minimum"):
                state_maintenance.require_heavy_capacity(Path("/tmp"))

    def test_success_cleanup_removes_only_disposable_heavy_files(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.state_root) as name:
            root = Path(name)
            disk = root / "target.raw"
            firmware = root / "nested/OVMF_VARS.4m.fd"
            key = root / "administrator_ed25519"
            evidence = root / "phase-acceptance.json"
            firmware.parent.mkdir()
            for path in (disk, firmware, key, evidence):
                path.write_text("fixture")
            removed = state_maintenance.cleanup_success_artifacts(root)
            self.assertEqual(len(removed), 3)
            self.assertTrue(evidence.is_file())
            self.assertFalse(disk.exists())
            self.assertFalse(firmware.exists())
            self.assertFalse(key.exists())

    def test_keep_artifacts_and_broad_target_are_safe(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.state_root) as name:
            root = Path(name)
            disk = root / "target.raw"
            disk.write_text("fixture")
            self.assertEqual(
                state_maintenance.cleanup_success_artifacts(root, keep_artifacts=True), []
            )
            self.assertTrue(disk.is_file())
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsafe"):
            state_maintenance.cleanup_success_artifacts(state_maintenance.STATE_ROOT)

    def test_generated_tree_cleanup_is_exact_and_guarded(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.state_root) as name:
            root = Path(name)
            generated = root / "work/commit"
            readonly = generated / "immutable/repository"
            readonly.mkdir(parents=True)
            (readonly / "large.file").write_text("fixture")
            readonly.chmod(0o555)
            self.assertTrue(
                state_maintenance.cleanup_generated_tree(generated, allowed_root=root)
            )
            self.assertFalse(generated.exists())
            self.assertTrue(root.is_dir())
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsafe"):
                state_maintenance.cleanup_generated_tree(root, allowed_root=root)

    def test_prepare_heavy_work_uses_managed_tmpdir(self) -> None:
        original_tempdir = tempfile.tempdir
        original_environment = state_maintenance.os.environ.get("TMPDIR")
        try:
            with tempfile.TemporaryDirectory(dir=self.state_root) as name:
                root = Path(name)
                usage = mock.Mock(
                    total=400 * state_maintenance.GIB,
                    used=100 * state_maintenance.GIB,
                    free=300 * state_maintenance.GIB,
                )
                with mock.patch.object(state_maintenance.shutil, "disk_usage", return_value=usage):
                    report = state_maintenance.prepare_heavy_work(root)
                self.assertEqual(report["status"], "qualified")
                self.assertEqual(Path(report["tmpdir"]), root / "tmp")
                self.assertEqual((root / "tmp").stat().st_mode & 0o777, 0o700)
        finally:
            tempfile.tempdir = original_tempdir
            if original_environment is None:
                state_maintenance.os.environ.pop("TMPDIR", None)
            else:
                state_maintenance.os.environ["TMPDIR"] = original_environment

    def test_phase88_retention_preserves_current_inputs_and_qualified_evidence(self) -> None:
        latest_iso = state_maintenance.STATE_ROOT / "phase4/out/ca3462a-current"
        latest_run = state_maintenance.STATE_ROOT / "phase88/iso/runs/current"
        preserve = (
            "phase88/generation",
            "phase88/input-g0004",
            "phase88/runs",
            "phase88/rescue",
            "phase88/iso/artifacts",
            "phase88/iso/runs/current",
            "phase88/static-ca3462a",
        )
        for relative in preserve:
            path = state_maintenance.STATE_ROOT / relative
            with self.subTest(path=relative):
                category, _, required, _ = state_maintenance.classify(
                    path, latest_iso, latest_run
                )
                self.assertEqual(category, "PRESERVE")
                self.assertTrue(required)

    def test_phase88_retention_deletes_only_superseded_or_scratch_state(self) -> None:
        latest_iso = state_maintenance.STATE_ROOT / "phase4/out/ca3462a-current"
        latest_run = state_maintenance.STATE_ROOT / "phase88/iso/runs/current"
        cases = {
            "phase88/diagnostic": "FAILED_OR_SCRATCH",
            "phase88/input-g0004-verify": "FAILED_OR_SCRATCH",
            "phase88/rescue-diagnostic": "FAILED_OR_SCRATCH",
            "phase88/static-old": "EVIDENCE_RECORDED_REBUILDABLE",
            "phase88/iso/runs/failed": "FAILED_OR_SCRATCH",
        }
        for relative, expected in cases.items():
            with self.subTest(path=relative):
                category, reproducible, required, _ = state_maintenance.classify(
                    state_maintenance.STATE_ROOT / relative, latest_iso, latest_run
                )
                self.assertEqual(category, expected)
                self.assertTrue(reproducible)
                self.assertFalse(required)

    def test_prune_uses_only_inventory_delete_categories(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.state_root) as name:
            root = Path(name)
            preserve = root / "preserve"
            delete = root / "delete"
            preserve.mkdir()
            delete.mkdir()
            (preserve / "value").write_text("keep")
            (delete / "value").write_text("remove")
            inventory = root / "inventory.json"
            receipt = root / "receipt.json"
            document = {
                "kind": "kitpro-state-retention-inventory",
                "entries": [
                    {"path": preserve.relative_to(state_maintenance.PROJECT_ROOT).as_posix(), "classification": "PRESERVE", "disk_usage_bytes": 1, "reason": "fixture"},
                    {"path": delete.relative_to(state_maintenance.PROJECT_ROOT).as_posix(), "classification": "FAILED_OR_SCRATCH", "disk_usage_bytes": 1, "reason": "fixture"},
                ],
            }
            inventory.write_text(json.dumps(document))
            result = state_maintenance.prune_inventory(inventory, receipt)
            self.assertEqual(result["status"], "passed")
            self.assertTrue(preserve.is_dir())
            self.assertFalse(delete.exists())

    def test_reconcile_records_exact_absent_candidates(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.state_root) as name:
            root = Path(name)
            absent = root / "already-deleted"
            remaining = root / "still-present"
            remaining.mkdir()
            inventory = root / "inventory.json"
            receipt = root / "receipt.json"
            inventory.write_text(json.dumps({
                "kind": "kitpro-state-retention-inventory",
                "entries": [
                    {"path": absent.relative_to(state_maintenance.PROJECT_ROOT).as_posix(), "classification": "FAILED_OR_SCRATCH", "disk_usage_bytes": 7, "reason": "fixture"},
                    {"path": remaining.relative_to(state_maintenance.PROJECT_ROOT).as_posix(), "classification": "EVIDENCE_RECORDED_REBUILDABLE", "disk_usage_bytes": 9, "reason": "fixture"},
                ],
            }))
            partial = state_maintenance.reconcile_inventory(inventory, receipt)
            self.assertEqual(partial["status"], "partial")
            self.assertEqual(partial["deleted_disk_usage_bytes"], 7)
            remaining.rmdir()
            passed = state_maintenance.reconcile_inventory(inventory, receipt)
            self.assertEqual(passed["status"], "passed")
            self.assertEqual(passed["deleted_path_count"], 2)


if __name__ == "__main__":
    unittest.main()
