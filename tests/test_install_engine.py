from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install import engine
from tools.install.disk import create_test_disk
from tools.install.engine import render_repart_definitions, validate_report
from tools.install.model import ABSOLUTE_MINIMUM_BYTES, parse_spec
from tools.install.plan import build_plan
from tests.test_install_plan import document as plan_document
from tests.plan_fixture import generation_fixture


ROOT = Path(__file__).resolve().parents[1]


def plan() -> dict[str, object]:
    return {
        "partition_table": {
            "esp": {"partition_uuid": "11111111-1111-4111-8111-111111111111"},
            "root": {"partition_uuid": "22222222-2222-4222-8222-222222222222"},
        }
    }


def report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "installer_version": "0.3.0-dev.1",
        "install_spec_version": 1,
        "install_spec_sha256": "a" * 64,
        "install_plan_sha256": "b" * 64,
        "release": "0.1-dev",
        "repository_generation": "0.1-dev-g0002",
        "package_count": 167,
        "target": {},
        "disk": {},
        "rootfs_manifest_sha256": "c" * 64,
        "kernel": {},
        "initramfs": {},
        "bootloader": {"name": "systemd-boot", "version": "systemd 261"},
        "install_receipt": {
            "path": "/var/lib/kitpro-linux/install-receipt.json",
            "sha256": "d" * 64,
        },
        "system": {},
        "network": {},
        "ssh": {},
        "firewall": {},
        "start_time": "2026-09-25T00:00:00Z",
        "completion_time": "2026-09-25T00:01:00Z",
        "first_boot": {"status": "not_run", "checks": {}},
        "result": "installed_pending_first_boot",
    }


class InstallEngineTests(unittest.TestCase):
    def test_report_schema_is_valid_json(self) -> None:
        json.loads((ROOT / "schemas/installation-report.schema.json").read_text())
        validate_report(report())

    def test_report_rejects_missing_or_invalid_fields(self) -> None:
        missing = report()
        del missing["disk"]
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "misses fields"):
            validate_report(missing)
        invalid = report()
        invalid["install_plan_sha256"] = "bad"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "invalid hash"):
            validate_report(invalid)
        invalid_bootloader = report()
        invalid_bootloader["bootloader"] = "systemd-boot"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "bootloader"):
            validate_report(invalid_bootloader)

    def test_repart_definitions_use_gpt_roles_and_grow_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            definitions = render_repart_definitions(Path(name), plan())
            esp = (definitions / "00-esp.conf").read_text()
            root = (definitions / "10-root.conf").read_text()
            self.assertIn("Type=esp", esp)
            self.assertIn("SizeMinBytes=256M", esp)
            self.assertIn("Type=root-x86-64", root)
            self.assertIn("Format=ext4", root)
            self.assertIn("SizeMinBytes=5G", root)
            self.assertIn("GrowFileSystem=yes", root)
            self.assertNotIn("SizeMaxBytes", root)

    def test_pre_disk_failures_record_the_exact_stage(self) -> None:
        for failed_stage in ("rootfs_staging", "configuration", "boot_setup"):
            with (
                self.subTest(failed_stage=failed_stage),
                generation_fixture(),
                tempfile.TemporaryDirectory() as name,
            ):
                temporary = Path(name)
                target = temporary / "disk.raw"
                create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
                spec = parse_spec(plan_document(target))
                install_plan = build_plan(spec)

                def fail_stage(
                    _spec: object, _plan: object, _receipt: object, callback: object
                ) -> object:
                    if failed_stage in {"configuration", "boot_setup"}:
                        callback("configuration")
                    if failed_stage == "boot_setup":
                        callback("boot_setup")
                    raise kitpro_repo.PipelineError(f"simulated {failed_stage} failure")

                evidence = temporary / "evidence"
                with (
                    mock.patch.object(engine, "INSTALLATION_ROOT", temporary / "installations"),
                    mock.patch.object(engine, "EVIDENCE_ROOT", evidence),
                    mock.patch.object(engine, "stage_rootfs", side_effect=fail_stage),
                ):
                    with self.assertRaisesRegex(kitpro_repo.PipelineError, "simulated"):
                        engine.apply(spec, install_plan, allow_disk_erase=True)
                failure = kitpro_repo.load_json(evidence / install_plan["plan_sha256"] / "failure.json")
                self.assertEqual(failure["failed_stage"], failed_stage)

    def test_repart_failure_preserves_partitioning_evidence(self) -> None:
        with generation_fixture(), tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            target = temporary / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            spec = parse_spec(plan_document(target))
            install_plan = build_plan(spec)
            staging = temporary / "work/rootfs"
            staging.mkdir(parents=True)

            def staged(
                _spec: object, _plan: object, _receipt: object, callback: object
            ) -> object:
                callback("configuration")
                callback("boot_setup")
                return staging, {}, {}

            evidence = temporary / "evidence"
            with (
                mock.patch.object(engine, "INSTALLATION_ROOT", temporary / "installations"),
                mock.patch.object(engine, "EVIDENCE_ROOT", evidence),
                mock.patch.object(engine, "stage_rootfs", side_effect=staged),
                mock.patch.object(
                    engine, "_run_repart",
                    side_effect=kitpro_repo.PipelineError(
                        "partitioning, formatting, or rootfs deployment failed"
                    ),
                ),
            ):
                with self.assertRaisesRegex(kitpro_repo.PipelineError, "formatting"):
                    engine.apply(spec, install_plan, allow_disk_erase=True)
            failure = kitpro_repo.load_json(evidence / install_plan["plan_sha256"] / "failure.json")
            self.assertEqual(failure["failed_stage"], "partitioning")
            self.assertIn("rootfs deployment", failure["error"])

    def test_block_install_uses_online_repart_population(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            evidence = temporary / "evidence"
            evidence.mkdir()
            completed = mock.Mock(returncode=0, stdout="[]", stderr="")
            with (
                mock.patch.object(engine.os, "geteuid", return_value=0),
                mock.patch.object(engine.subprocess, "run", return_value=completed) as run,
                mock.patch.object(engine, "_mtools_environment", return_value={}),
            ):
                engine._run_repart(
                    Path("/dev/vda"), "block", temporary / "rootfs",
                    temporary / "repart.d", evidence,
                )
            command = run.call_args.args[0]
            self.assertIn("--offline=no", command)
            self.assertIn("--empty=require", command)
            self.assertNotIn("--empty=force", command)
            self.assertNotIn("--offline=yes", command)

    def test_image_install_keeps_offline_repart_population(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            evidence = temporary / "evidence"
            evidence.mkdir()
            completed = mock.Mock(returncode=0, stdout="[]", stderr="")
            with (
                mock.patch.object(engine.subprocess, "run", return_value=completed) as run,
                mock.patch.object(engine, "_mtools_environment", return_value={}),
            ):
                engine._run_repart(
                    temporary / "disk.raw", "image", temporary / "rootfs",
                    temporary / "repart.d", evidence,
                )
            command = run.call_args.args[0]
            self.assertIn("--offline=yes", command)
            self.assertIn("--empty=force", command)

    def test_physical_target_is_wiped_reread_settled_and_verified_before_repart(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            target = temporary / "nvme0n1"
            target.write_bytes(b"")
            evidence = temporary / "evidence"
            evidence.mkdir()
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            after = [{"path": str(target), "type": "disk", "size": 512_000_000_000}]
            with (
                mock.patch.object(engine.os, "geteuid", return_value=0),
                mock.patch.object(
                    engine, "_assert_block_target_idle", side_effect=[[], after]
                ) as idle,
                mock.patch.object(
                    engine, "_recorded_command", return_value=completed
                ) as command,
            ):
                engine._prepare_block_target(
                    target, {"size_bytes": 512_000_000_000}, evidence
                )
            self.assertEqual(
                [call.args[0] for call in command.call_args_list],
                [
                    ["wipefs", "--all", "--force", str(target)],
                    ["udevadm", "settle", "--timeout=30"],
                    ["blockdev", "--rereadpt", str(target)],
                    ["udevadm", "settle", "--timeout=30"],
                ],
            )
            self.assertFalse(idle.call_args_list[0].kwargs["require_no_children"])
            self.assertTrue(idle.call_args_list[1].kwargs["require_no_children"])

    def test_stale_partition_nodes_fail_closed_after_reread(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "kitpro-test-target"
            target.write_bytes(b"")
            devices = [
                {"path": str(target), "type": "disk", "size": 10, "mountpoints": []},
                {"path": str(target) + "p1", "type": "part", "size": 5, "mountpoints": []},
            ]
            with (
                mock.patch.object(engine, "_block_tree", return_value=devices),
                mock.patch.object(engine, "_device_is_swap", return_value=False),
            ):
                with self.assertRaisesRegex(
                    kitpro_repo.PipelineError, "stale partition devices remain"
                ):
                    engine._assert_block_target_idle(
                        target,
                        Path(name),
                        require_no_children=True,
                        name="after-wipe",
                    )

    def test_first_boot_failure_marks_installation_failed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "installation-report.json"
            value = report()
            value["target"] = {"target_type": "block", "path": "/dev/test"}
            kitpro_repo.atomic_write_json(path, value)
            updated = engine.update_first_boot_report(
                path, {"status": "failed", "checks": {}, "error": "boot timeout"}
            )
            self.assertEqual(updated["result"], "failed")
            self.assertEqual(updated["first_boot"]["error"], "boot timeout")


if __name__ == "__main__":
    unittest.main()
