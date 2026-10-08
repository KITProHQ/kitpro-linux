from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install.receipt import build_receipt
from tools.install.render import loader_entry
from tools.rescue import (
    detect_root,
    inspect_kernel_state,
    inspect_root,
    kernel_status,
    regenerate_initramfs,
    regenerate_previous_initramfs,
    repair_boot,
    repair_fallback_entry,
    require_confirmation,
    validate_recovery_receipt,
)


KERNEL_RUNTIME = Path(__file__).resolve().parents[1] / "runtime/kernel-lifecycle"
KERNEL_RELEASE = "6.18.53-1-lts"
NEW_KERNEL_RELEASE = "6.18.54-1-lts"


def plan() -> dict[str, object]:
    return {
        "installer_version": "0.8.0-dev.1",
        "release": "0.1-dev",
        "repository_generation": "0.1-dev-g0002",
        "install_spec_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "repository": {"generation_manifest_sha256": "c" * 64},
        "partition_table": {
            "esp": {"partition_uuid": "11111111-1111-4111-8111-111111111111"},
            "root": {"partition_uuid": "22222222-2222-4222-8222-222222222222"},
        },
    }


def fixture(root: Path) -> None:
    for relative in (
        "etc/systemd/network", "etc/ssh/sshd_config.d", "boot", "efi/loader/entries",
        "var/lib/pacman/local/base-3-3", "var/lib/kitpro-linux", "var/log/journal",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    (root / "etc/os-release").write_text(
        'NAME="KITPro Linux Server"\nID=kitpro-linux\nVERSION_ID="0.1-dev"\nBUILD_ID="0.1-dev-g0002"\n'
    )
    kitpro_repo.atomic_write_json(
        root / "etc/kitpro-linux-release.json",
        {"schema_version": 1, "release": "0.1-dev", "generation": "0.1-dev-g0002", "channel": "stable", "production_ready": False},
    )
    (root / "etc/hostname").write_text("rescued-host\n")
    receipt = build_receipt(plan(), "2026-09-26T00:00:00Z", {"kind": "development-environment"})
    kitpro_repo.atomic_write_json(root / "var/lib/kitpro-linux/install-receipt.json", receipt)
    (root / "boot/vmlinuz-linux-lts").write_bytes(b"kernel")
    (root / "boot/initramfs-linux-lts.img").write_bytes(b"initramfs")
    modules = root / "usr/lib/modules" / KERNEL_RELEASE
    modules.mkdir(parents=True)
    (modules / "pkgbase").write_text("linux-lts\n")
    (modules / "vmlinuz").write_bytes(b"kernel")
    shutil.copy2(root / "boot/vmlinuz-linux-lts", root / "efi/vmlinuz-linux-lts")
    shutil.copy2(root / "boot/initramfs-linux-lts.img", root / "efi/initramfs-linux-lts.img")
    (root / "efi/loader/loader.conf").write_text("default kitpro-linux.conf\n")
    (root / "efi/loader/entries/kitpro-linux.conf").write_text(
        loader_entry("22222222-2222-4222-8222-222222222222")
    )
    (root / "etc/pacman.conf").write_text(
        "[options]\nSigLevel = Required DatabaseRequired TrustedOnly\n"
        "LocalFileSigLevel = Required TrustedOnly\n"
        "[kitpro-0.1-dev-core]\nSigLevel = Required DatabaseRequired TrustedOnly\n"
        "Server = https://repo.invalid/stable/0.1-dev/0.1-dev-g0002/core/os/$arch\n"
    )
    (root / "etc/systemd/network/20-kitpro.network").write_text(
        "[Match]\nName=en*\n\n[Network]\nDHCP=yes\n"
    )
    os.symlink("../run/systemd/resolve/stub-resolv.conf", root / "etc/resolv.conf")
    (root / "etc/nftables.conf").write_text(
        'table inet filter { chain input { type filter hook input priority filter; policy drop; iifname "lo" accept ct state established,related accept } }\n'
    )
    (root / "etc/ssh/sshd_config.d/10-kitpro-server.conf").write_text(
        "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
    )
    subprocess.run(
        [
            str(KERNEL_RUNTIME), "--root", str(root), "initialize",
            "--package-version", "6.18.53-1",
            "--generation", "0.1-dev-g0002",
            "--root-partuuid", "22222222-2222-4222-8222-222222222222",
            "--kernel-release", KERNEL_RELEASE,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    environment = os.environ.copy()
    environment["KITPRO_RUNNING_KERNEL"] = KERNEL_RELEASE
    subprocess.run(
        [str(KERNEL_RUNTIME), "--root", str(root), "record-successful-boot"],
        check=True,
        env=environment,
        stdout=subprocess.DEVNULL,
    )


def fallback_fixture(root: Path) -> None:
    fixture(root)
    environment = os.environ.copy()
    environment.update(
        {
            "KITPRO_RUNNING_KERNEL": KERNEL_RELEASE,
            "KITPRO_TEST_ROOT_FREE_BYTES": str(2**40),
            "KITPRO_TEST_ESP_FREE_BYTES": str(2**40),
        }
    )
    subprocess.run(
        [str(KERNEL_RUNTIME), "--root", str(root), "stage"],
        check=True,
        env=environment,
        stdout=subprocess.DEVNULL,
    )
    shutil.rmtree(root / "usr/lib/modules" / KERNEL_RELEASE)
    modules = root / "usr/lib/modules" / NEW_KERNEL_RELEASE
    modules.mkdir(parents=True)
    (modules / "pkgbase").write_text("linux-lts\n")
    (modules / "vmlinuz").write_bytes(b"kernel-b")
    (modules / "kernel-test.ko").write_bytes(b"module-b")
    (root / "boot/vmlinuz-linux-lts").write_bytes(b"kernel-b")
    (root / "boot/initramfs-linux-lts.img").write_bytes(b"initramfs-b")
    (root / "etc/kitpro-linux-release.json").write_text(
        '{"generation":"0.1-dev-g0003"}\n'
    )
    environment = os.environ.copy()
    environment.update(
        {
            "KITPRO_NEW_KERNEL_RELEASE": NEW_KERNEL_RELEASE,
            "KITPRO_NEW_PACKAGE_VERSION": "6.18.54-1",
            "KITPRO_NEW_GENERATION": "0.1-dev-g0003",
        }
    )
    subprocess.run(
        [str(KERNEL_RUNTIME), "--root", str(root), "activate"],
        check=True,
        env=environment,
        stdout=subprocess.DEVNULL,
    )


class RescueTests(unittest.TestCase):
    def test_kernel_status_reuses_lifecycle_model_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fallback_fixture(root)
            state = json.loads((root / "var/lib/kitpro-linux/kernel-state.json").read_text())
            tracked = [
                root / "var/lib/kitpro-linux/kernel-state.json",
                root / state["current_kernel_image_path"].removeprefix("/"),
                root / state["current_initramfs_path"].removeprefix("/"),
                root / state["previous_kernel_image_path"].removeprefix("/"),
                root / state["previous_initramfs_path"].removeprefix("/"),
                root / state["current_boot_entry"].removeprefix("/"),
                root / state["previous_boot_entry"].removeprefix("/"),
                root / "etc/pacman.conf",
            ]
            before = {path: kitpro_repo.sha256_file(path) for path in tracked}
            report, exit_code = kernel_status(root)
            after = {path: kitpro_repo.sha256_file(path) for path in tracked}
            self.assertEqual(exit_code, 1)
            self.assertEqual(report["boot_mode"], "unavailable")
            self.assertEqual(report["candidate"]["status"], "pending-validation")
            self.assertEqual(report["fallback"]["availability"], "yes")
            self.assertEqual(after, before)

    def test_kernel_status_uses_live_bash_for_noexec_rescue_mounts(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            commands: list[list[str]] = []
            actual_run = subprocess.run

            def record(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                return actual_run(command, **kwargs)

            with mock.patch("tools.rescue.subprocess.run", side_effect=record):
                report, exit_code = kernel_status(root)
            self.assertEqual(exit_code, 0)
            self.assertEqual(report["overall_status"], "healthy")
            self.assertEqual(commands[0][0], "/usr/bin/bash")
            self.assertEqual(commands[0][1], str(KERNEL_RUNTIME))

    def test_detect_and_healthy_inspection_are_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            before = sorted(path.relative_to(root) for path in root.rglob("*"))
            detected = detect_root(root, "/dev/vda2", "ext4")
            report = inspect_root(root)
            after = sorted(path.relative_to(root) for path in root.rglob("*"))
            self.assertEqual(detected["generation"], "0.1-dev-g0002")
            self.assertEqual(report["status"], "healthy")
            self.assertEqual(report["filesystem"]["integrity"], "not-checked")
            self.assertEqual(before, after)

    def test_non_kitpro_root_is_not_detected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "etc").mkdir()
            (root / "etc/os-release").write_text("ID=arch\n")
            self.assertIsNone(detect_root(root))

    def test_health_classifies_initramfs_boot_repository_firewall_and_ssh_failures(self) -> None:
        corruptions = {
            "initramfs": lambda root: (root / "boot/initramfs-linux-lts.img").unlink(),
            "boot_entry": lambda root: (root / "efi/loader/entries/kitpro-linux.conf").unlink(),
            "repository": lambda root: (root / "etc/pacman.conf").write_text("[core]\nServer=https://arch.invalid\n"),
            "nftables": lambda root: (root / "etc/nftables.conf").write_text("invalid\n"),
            "sshd": lambda root: (root / "etc/ssh/sshd_config.d/10-kitpro-server.conf").write_text("PermitRootLogin yes\n"),
        }
        for check, corrupt in corruptions.items():
            with self.subTest(check=check), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                fixture(root)
                corrupt(root)
                report = inspect_root(root)
                self.assertEqual(report["status"], "degraded")
                self.assertFalse(report["checks"][check])

    def test_write_confirmation_is_exact(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "exact confirmation"):
            require_confirmation("yes", "REPAIR BOOT /mnt")

    def test_initramfs_repair_uses_mkinitcpio_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            (root / "boot/initramfs-linux-lts.img").unlink()
            (root / "efi/initramfs-linux-lts.img").unlink()
            commands: list[list[str]] = []

            def fake_run(command: list[str]) -> None:
                commands.append(command)
                if command[-1] == "-P":
                    (root / "boot/initramfs-linux-lts.img").write_bytes(b"repaired")
                elif command[-1] == "refresh-current-artifacts":
                    subprocess.run(
                        [str(KERNEL_RUNTIME), "--root", str(root), "refresh-current-artifacts"],
                        check=True,
                    )

            with mock.patch("tools.rescue.os.path.ismount", return_value=True):
                receipt_path, receipt = regenerate_initramfs(
                    root, f"REGENERATE INITRAMFS {root.resolve()}", fake_run
                )
            self.assertEqual(commands[0], ["arch-chroot", str(root.resolve()), "mkinitcpio", "-P"])
            self.assertEqual(commands[1][-1], "refresh-current-artifacts")
            state = kitpro_repo.load_json(root / "var/lib/kitpro-linux/kernel-state.json")
            self.assertTrue((root / state["current_initramfs_path"].removeprefix("/")).is_file())
            self.assertEqual(receipt["operation"], "regenerate-initramfs")
            self.assertTrue(receipt_path.is_file())
            self.assertRegex(receipt["receipt_sha256"], r"^[0-9a-f]{64}$")
            validate_recovery_receipt(receipt)

    def test_boot_entry_repair_uses_shared_renderer_and_writes_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            (root / "efi/loader/entries/kitpro-linux.conf").unlink()
            commands: list[list[str]] = []
            def fake_run(command: list[str]) -> None:
                commands.append(command)
                if command[-1] == "refresh-current-artifacts":
                    subprocess.run(
                        [str(KERNEL_RUNTIME), "--root", str(root), "refresh-current-artifacts"],
                        check=True,
                    )
            with mock.patch("tools.rescue.os.path.ismount", return_value=True):
                receipt_path, receipt = repair_boot(
                    root,
                    f"REPAIR BOOT {root.resolve()}",
                    fake_run,
                )
            self.assertIn("bootctl", commands[0][0])
            entry = (root / "efi/loader/entries/kitpro-linux.conf").read_text()
            self.assertIn("root=PARTUUID=22222222-2222-4222-8222-222222222222", entry)
            self.assertEqual(receipt["operation"], "repair-boot")
            self.assertTrue(receipt_path.is_file())

    def test_repair_refuses_unmounted_esp(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "ESP must be explicitly mounted"):
                repair_boot(root, f"REPAIR BOOT {root.resolve()}", lambda _command: None)

    def test_started_failed_repair_still_writes_failed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture(root)
            with (
                mock.patch("tools.rescue.os.path.ismount", return_value=True),
                self.assertRaisesRegex(kitpro_repo.PipelineError, "controlled failure"),
            ):
                regenerate_initramfs(
                    root,
                    f"REGENERATE INITRAMFS {root.resolve()}",
                    lambda _command: (_ for _ in ()).throw(
                        kitpro_repo.PipelineError("controlled failure")
                    ),
                )
            receipts = list((root / "var/lib/kitpro-linux/recovery").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = kitpro_repo.load_json(receipts[0])
            self.assertEqual(receipt["result"], "failed")
            validate_recovery_receipt(receipt)

    def test_fallback_inspection_and_missing_entry_repair(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fallback_fixture(root)
            lifecycle = inspect_kernel_state(root)
            self.assertTrue(lifecycle["valid"])
            self.assertEqual(lifecycle["previous"]["kernel_release"], KERNEL_RELEASE)
            entry = root / "efi/loader/entries/kitpro-linux-previous.conf"
            entry.unlink()

            def fake_run(command: list[str]) -> None:
                self.assertEqual(command[-1], "repair-fallback-entry")
                subprocess.run(
                    [str(KERNEL_RUNTIME), "--root", str(root), "repair-fallback-entry"],
                    check=True,
                )

            with mock.patch("tools.rescue.os.path.ismount", return_value=True):
                receipt_path, receipt = repair_fallback_entry(
                    root, f"REPAIR FALLBACK ENTRY {root.resolve()}", fake_run
                )
            self.assertTrue(entry.is_file())
            self.assertTrue(inspect_kernel_state(root)["previous"]["boot_entry_valid"])
            self.assertEqual(receipt["operation"], "repair-fallback-entry")
            self.assertTrue(receipt_path.is_file())

    def test_previous_initramfs_repair_requires_retained_modules(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fallback_fixture(root)
            lifecycle = inspect_kernel_state(root)
            initramfs = root / lifecycle["previous"]["initramfs_path"].removeprefix("/")
            initramfs.unlink()

            def fake_run(command: list[str]) -> None:
                self.assertEqual(command[-1], "regenerate-previous-initramfs")
                initramfs.write_bytes(b"initramfs")
                subprocess.run(
                    [str(KERNEL_RUNTIME), "--root", str(root), "repair-fallback-entry"],
                    check=True,
                )

            with mock.patch("tools.rescue.os.path.ismount", return_value=True):
                receipt_path, receipt = regenerate_previous_initramfs(
                    root,
                    f"REGENERATE PREVIOUS INITRAMFS {root.resolve()}",
                    fake_run,
                )
            self.assertTrue(inspect_kernel_state(root)["previous"]["initramfs_valid"])
            self.assertEqual(receipt["operation"], "regenerate-previous-initramfs")
            self.assertTrue(receipt_path.is_file())

    def test_recovery_schemas_are_valid_json(self) -> None:
        root = Path(__file__).resolve().parents[1]
        json.loads((root / "schemas/recovery-receipt.schema.json").read_text())
        json.loads((root / "schemas/rescue-health.schema.json").read_text())


if __name__ == "__main__":
    unittest.main()
