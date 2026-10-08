from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT_ROOT / "runtime/kernel-lifecycle"
PARTUUID = "22222222-2222-4222-8222-222222222222"
A_PACKAGE = "6.18.53-1"
A_RELEASE = "6.18.53-1-lts"
B_PACKAGE = "6.18.54-1"
B_RELEASE = "6.18.54-1-lts"
C_PACKAGE = "6.18.55-1"
C_RELEASE = "6.18.55-1-lts"


def write_package(root: Path, package_version: str, kernel_release: str) -> None:
    modules = root / "usr/lib/modules" / kernel_release
    modules.mkdir(parents=True, exist_ok=True)
    (modules / "pkgbase").write_text("linux-lts\n")
    (modules / "vmlinuz").write_bytes(("kernel-" + kernel_release).encode())
    (modules / "kernel-test.ko").write_bytes(("module-" + kernel_release).encode())
    (root / "boot").mkdir(parents=True, exist_ok=True)
    shutil.copy2(modules / "vmlinuz", root / "boot/vmlinuz-linux-lts")
    (root / "boot/initramfs-linux-lts.img").write_bytes(
        ("initramfs-" + kernel_release).encode()
    )
    local = root / "var/lib/pacman/local"
    local.mkdir(parents=True, exist_ok=True)
    for old in local.glob("linux-lts-*"):
        shutil.rmtree(old)
    desc = local / f"linux-lts-{package_version}/desc"
    desc.parent.mkdir(parents=True)
    desc.write_text(f"%NAME%\nlinux-lts\n\n%VERSION%\n{package_version}\n")


def write_generation(root: Path, generation: str) -> None:
    path = root / "etc/kitpro-linux-release.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"generation": generation}) + "\n")


class KernelLifecycleTests(unittest.TestCase):
    def run_lifecycle(
        self,
        root: Path,
        *arguments: str,
        running: str | None = None,
        root_free: int | None = None,
        esp_free: int | None = None,
        success: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        if running:
            environment["KITPRO_RUNNING_KERNEL"] = running
        if root_free is not None:
            environment["KITPRO_TEST_ROOT_FREE_BYTES"] = str(root_free)
        if esp_free is not None:
            environment["KITPRO_TEST_ESP_FREE_BYTES"] = str(esp_free)
        completed = subprocess.run(
            [str(RUNTIME), "--root", str(root), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=environment,
        )
        if success and completed.returncode != 0:
            self.fail(completed.stdout)
        if not success and completed.returncode == 0:
            self.fail("lifecycle command unexpectedly passed")
        return completed

    def fixture(self, root: Path) -> None:
        (root / "efi/loader/entries").mkdir(parents=True)
        write_package(root, A_PACKAGE, A_RELEASE)
        write_generation(root, "0.1-dev-g0002")
        self.run_lifecycle(
            root,
            "initialize",
            "--package-version",
            A_PACKAGE,
            "--generation",
            "0.1-dev-g0002",
            "--root-partuuid",
            PARTUUID,
            "--kernel-release",
            A_RELEASE,
        )

    def state(self, root: Path) -> dict[str, object]:
        return json.loads((root / "var/lib/kitpro-linux/kernel-state.json").read_text())

    def mark_a_good(self, root: Path) -> None:
        self.run_lifecycle(root, "record-successful-boot", running=A_RELEASE)

    def transition_to_b(self, root: Path) -> None:
        self.run_lifecycle(
            root,
            "stage",
            running=A_RELEASE,
            root_free=2**40,
            esp_free=2**40,
        )
        shutil.rmtree(root / "usr/lib/modules" / A_RELEASE)
        write_package(root, B_PACKAGE, B_RELEASE)
        write_generation(root, "0.1-dev-g0003")
        environment = os.environ.copy()
        environment.update(
            {
                "KITPRO_NEW_KERNEL_RELEASE": B_RELEASE,
                "KITPRO_NEW_PACKAGE_VERSION": B_PACKAGE,
                "KITPRO_NEW_GENERATION": "0.1-dev-g0003",
            }
        )
        completed = subprocess.run(
            [str(RUNTIME), "--root", str(root), "activate"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=environment,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)

    def test_fresh_install_has_candidate_current_and_no_fake_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            state = self.state(root)
            self.assertEqual(state["state"], "candidate")
            self.assertEqual(state["candidate_status"], "pending-first-boot")
            self.assertIsNone(state["previous_kernel_release"])
            self.assertTrue((root / "efi/loader/entries/kitpro-linux.conf").is_file())
            compatibility = (
                root / "efi/loader/entries/kitpro-linux-compatibility.conf"
            ).read_text()
            self.assertIn("console=ttyS0,115200n8 console=tty0 nomodeset", compatibility)
            self.assertIn("Compatibility Graphics", compatibility)
            self.assertNotIn("systemd.debug_shell", compatibility)
            self.assertFalse(
                (root / "efi/loader/entries/kitpro-linux-previous.conf").exists()
            )

    def test_normal_transition_retains_modules_and_manual_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            self.transition_to_b(root)
            state = self.state(root)
            self.assertEqual(state["state"], "candidate")
            self.assertEqual(state["current_kernel_release"], B_RELEASE)
            self.assertEqual(state["previous_kernel_release"], A_RELEASE)
            self.assertTrue((root / "usr/lib/modules" / A_RELEASE).is_dir())
            fallback = (root / "efi/loader/entries/kitpro-linux-previous.conf").read_text()
            fallback_compatibility = (
                root / "efi/loader/entries/kitpro-linux-previous-compatibility.conf"
            ).read_text()
            self.assertIn(f"Previous Kernel {A_RELEASE}", fallback)
            self.assertIn(f"linux /EFI/KITPro/kernels/{A_RELEASE}/vmlinuz-linux-lts", fallback)
            self.assertNotIn("linux /efi/", fallback)
            self.assertIn(f"/kernels/{A_RELEASE}/vmlinuz-linux-lts", fallback)
            self.assertIn("nomodeset", fallback_compatibility)
            self.assertEqual(
                (root / "efi/loader/loader.conf").read_text().splitlines()[0],
                "default kitpro-linux.conf",
            )
            self.run_lifecycle(root, "record-successful-boot", running=B_RELEASE)
            state = self.state(root)
            self.assertEqual(state["state"], "known-good")
            self.assertEqual(state["candidate_status"], "validated")
            self.run_lifecycle(root, "validate-fallback")
            self.run_lifecycle(root, "record-successful-boot", running=A_RELEASE)
            state = self.state(root)
            self.assertEqual(state["current_kernel_release"], B_RELEASE)
            self.assertEqual(state["previous_kernel_release"], A_RELEASE)
            self.assertEqual(state["last_successful_boot_role"], "previous-known-good")

    def test_failed_candidate_does_not_promote_or_damage_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            self.transition_to_b(root)
            (root / "efi/loader/entries/kitpro-linux.conf").write_text("invalid\n")
            state = self.state(root)
            self.assertEqual(state["state"], "candidate")
            self.assertEqual(state["candidate_status"], "pending-validation")
            self.assertEqual(state["previous_kernel_release"], A_RELEASE)
            self.run_lifecycle(root, "validate-fallback")
            self.run_lifecycle(root, "record-successful-boot", running=A_RELEASE)
            self.assertEqual(self.state(root)["state"], "candidate")

    def test_missing_fallback_entry_is_recreated_from_retained_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            self.transition_to_b(root)
            entry = root / "efi/loader/entries/kitpro-linux-previous.conf"
            entry.unlink()
            self.run_lifecycle(root, "repair-fallback-entry")
            self.assertTrue(entry.is_file())
            self.run_lifecycle(root, "validate-fallback")

    def test_disk_space_guard_fails_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            completed = self.run_lifecycle(
                root,
                "stage",
                running=A_RELEASE,
                root_free=1,
                esp_free=1,
                success=False,
            )
            self.assertIn("insufficient space for safe kernel retention", completed.stdout)
            state = self.state(root)
            self.assertEqual(state["state"], "known-good")
            self.assertEqual(state["transition_stage"], "complete")
            self.assertFalse((root / "var/lib/kitpro-linux/kernel-transition").exists())

    def test_second_successful_transition_removes_only_superseded_a(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            self.transition_to_b(root)
            self.run_lifecycle(root, "record-successful-boot", running=B_RELEASE)
            self.run_lifecycle(
                root,
                "stage",
                running=B_RELEASE,
                root_free=2**40,
                esp_free=2**40,
            )
            shutil.rmtree(root / "usr/lib/modules" / B_RELEASE)
            write_package(root, C_PACKAGE, C_RELEASE)
            write_generation(root, "0.1-dev-g0004")
            environment = os.environ.copy()
            environment.update(
                {
                    "KITPRO_NEW_KERNEL_RELEASE": C_RELEASE,
                    "KITPRO_NEW_PACKAGE_VERSION": C_PACKAGE,
                    "KITPRO_NEW_GENERATION": "0.1-dev-g0004",
                }
            )
            subprocess.run(
                [str(RUNTIME), "--root", str(root), "activate"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            self.assertTrue((root / "usr/lib/modules" / A_RELEASE).is_dir())
            self.run_lifecycle(root, "record-successful-boot", running=C_RELEASE)
            state = self.state(root)
            self.assertEqual(state["current_kernel_release"], C_RELEASE)
            self.assertEqual(state["previous_kernel_release"], B_RELEASE)
            self.assertFalse((root / "usr/lib/modules" / A_RELEASE).exists())
            self.assertTrue((root / "usr/lib/modules" / B_RELEASE).is_dir())

    def test_transition_receipt_and_schemas_are_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.mark_a_good(root)
            self.transition_to_b(root)
            self.run_lifecycle(root, "record-successful-boot", running=B_RELEASE)
            receipts = list((root / "var/lib/kitpro-linux/kernel-transitions").glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text())
            self.assertEqual(receipt["result"], "passed")
            self.assertEqual(receipt["candidate_health_result"], "passed")
            self.assertRegex(receipt["receipt_sha256"], r"^[0-9a-f]{64}$")
        json.loads((PROJECT_ROOT / "schemas/kernel-state.schema.json").read_text())
        json.loads(
            (PROJECT_ROOT / "schemas/kernel-transition-receipt.schema.json").read_text()
        )


if __name__ == "__main__":
    unittest.main()
