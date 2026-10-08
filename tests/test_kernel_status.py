from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_kernel_lifecycle import (
    A_PACKAGE,
    A_RELEASE,
    B_PACKAGE,
    B_RELEASE,
    PARTUUID,
    write_generation,
    write_package,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT_ROOT / "runtime/kernel-lifecycle"
COMMAND = PROJECT_ROOT / "runtime/kitpro-kernel-status"


class KernelStatusTests(unittest.TestCase):
    def lifecycle(
        self,
        root: Path,
        *arguments: str,
        running: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        values = os.environ.copy()
        if running is not None:
            values["KITPRO_RUNNING_KERNEL"] = running
        values.update(environment or {})
        completed = subprocess.run(
            [str(RUNTIME), "--root", str(root), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=values,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)
        return completed

    def status(
        self,
        root: Path,
        running: str = A_RELEASE,
        root_free: int = 2**40,
        esp_free: int = 2**40,
        wrapper: bool = False,
        human: bool = False,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
        environment = os.environ.copy()
        environment["KITPRO_TEST_ROOT_FREE_BYTES"] = str(root_free)
        environment["KITPRO_TEST_ESP_FREE_BYTES"] = str(esp_free)
        if wrapper:
            environment["KITPRO_KERNEL_LIFECYCLE"] = str(RUNTIME)
            command = [str(COMMAND)]
        else:
            command = [str(RUNTIME), "--root", str(root), "status"]
        if not human:
            command.append("--json")
        command.extend(["--running-kernel", running])
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        return completed, None if human else json.loads(completed.stdout)

    def fixture(self, root: Path, mark_good: bool = True) -> None:
        (root / "efi/loader/entries").mkdir(parents=True)
        write_package(root, A_PACKAGE, A_RELEASE)
        write_generation(root, "0.1-dev-g0002")
        (root / "etc/pacman.conf").write_text(
            "[options]\nSigLevel = Required DatabaseRequired\n[kitpro-stable-core]\n"
        )
        self.lifecycle(
            root,
            "initialize",
            "--package-version", A_PACKAGE,
            "--generation", "0.1-dev-g0002",
            "--root-partuuid", PARTUUID,
            "--kernel-release", A_RELEASE,
        )
        if mark_good:
            self.lifecycle(root, "record-successful-boot", running=A_RELEASE)

    def transition(self, root: Path) -> None:
        self.lifecycle(
            root,
            "stage",
            running=A_RELEASE,
            environment={
                "KITPRO_TEST_ROOT_FREE_BYTES": str(2**40),
                "KITPRO_TEST_ESP_FREE_BYTES": str(2**40),
            },
        )
        shutil.rmtree(root / "usr/lib/modules" / A_RELEASE)
        write_package(root, B_PACKAGE, B_RELEASE)
        write_generation(root, "0.1-dev-g0003")
        self.lifecycle(
            root,
            "activate",
            environment={
                "KITPRO_NEW_KERNEL_RELEASE": B_RELEASE,
                "KITPRO_NEW_PACKAGE_VERSION": B_PACKAGE,
                "KITPRO_NEW_GENERATION": "0.1-dev-g0003",
            },
        )

    @staticmethod
    def evidence_hashes(root: Path) -> dict[str, str]:
        selected = [
            root / "var/lib/kitpro-linux/kernel-state.json",
            root / "etc/pacman.conf",
        ]
        selected.extend(sorted((root / "efi/loader/entries").glob("*.conf")))
        selected.extend(sorted((root / "efi/EFI/KITPro/kernels").rglob("*")))
        selected.extend(sorted((root / "usr/lib/modules").rglob("*")))
        selected.extend(sorted((root / "var/lib/pacman/local").rglob("*")))
        return {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in selected
            if path.is_file()
        }

    def test_healthy_current_human_json_schema_and_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            completed, report = self.status(root)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            assert report is not None
            self.assertEqual(report["overall_status"], "healthy")
            self.assertEqual(report["boot_mode"], "current")
            self.assertTrue(report["expected_running_kernel_match"])
            self.assertEqual(report["current"]["repository_generation"], "0.1-dev-g0002")
            self.assertEqual(report["fallback"]["availability"], "no")
            self.assertEqual(report["retention_preflight"]["result"], "ready")
            human, _ = self.status(root, human=True)
            self.assertEqual(human.returncode, 0, human.stderr)
            self.assertIn("KITPro Linux Kernel Status", human.stdout)
            self.assertIn("Overall status:          healthy", human.stdout)
            environment = os.environ.copy()
            environment["KITPRO_KERNEL_LIFECYCLE"] = str(RUNTIME)
            wrapped = subprocess.run(
                [str(COMMAND), "--help"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                env=environment,
            )
            self.assertEqual(wrapped.returncode, 0, wrapped.stderr)
            self.assertIn("usage: kitpro-kernel-status", wrapped.stdout)
        schema = json.loads((PROJECT_ROOT / "schemas/kernel-status.schema.json").read_text())
        self.assertEqual(schema["properties"]["kind"]["const"], "kitpro-kernel-status")

    def test_fresh_install_and_candidate_pending_states(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root, mark_good=False)
            completed, report = self.status(root)
            self.assertEqual(completed.returncode, 1)
            assert report is not None
            self.assertTrue(report["candidate"]["present"])
            self.assertEqual(report["candidate"]["status"], "pending-first-boot")
            self.assertFalse(report["previous_known_good"]["present"])
            self.assertEqual(
                report["fallback"]["reason"],
                "No previous known-good kernel has been retained yet.",
            )
            self.assertFalse(report["reboot_required"])

            self.lifecycle(root, "record-successful-boot", running=A_RELEASE)
            self.transition(root)
            completed, report = self.status(root, running=A_RELEASE)
            self.assertEqual(completed.returncode, 1)
            assert report is not None
            self.assertEqual(report["candidate"]["status"], "pending-validation")
            self.assertTrue(report["reboot_required"])
            self.assertEqual(report["fallback"]["availability"], "yes")

    def test_validated_candidate_and_manual_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.transition(root)
            self.lifecycle(root, "record-successful-boot", running=B_RELEASE)
            completed, report = self.status(root, running=B_RELEASE)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            assert report is not None
            self.assertFalse(report["candidate"]["present"])
            self.assertEqual(report["current"]["state"], "known-good")
            completed, report = self.status(root, running=A_RELEASE)
            self.assertEqual(completed.returncode, 1)
            assert report is not None
            self.assertEqual(report["boot_mode"], "previous-known-good")
            self.assertFalse(report["expected_running_kernel_match"])
            self.assertTrue(report["reboot_required"])

    def test_damaged_fallback_components_are_warnings(self) -> None:
        cases = {
            "initramfs": lambda root, state: (root / state["previous_initramfs_path"].lstrip("/")).unlink(),
            "modules": lambda root, state: shutil.rmtree(root / state["previous_module_tree"].lstrip("/")),
            "entry": lambda root, state: (root / state["previous_boot_entry"].lstrip("/")).unlink(),
        }
        for label, damage in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                self.fixture(root)
                self.transition(root)
                self.lifecycle(root, "record-successful-boot", running=B_RELEASE)
                state = json.loads((root / "var/lib/kitpro-linux/kernel-state.json").read_text())
                damage(root, state)
                completed, report = self.status(root, running=B_RELEASE)
                self.assertEqual(completed.returncode, 1)
                assert report is not None
                self.assertEqual(report["fallback"]["availability"], "degraded")
                self.assertFalse(report["fallback"]["available"])

    def test_unexpected_kernel_and_bad_metadata_are_errors(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            completed, report = self.status(root, running="9.9.9-untracked")
            self.assertEqual(completed.returncode, 2)
            assert report is not None
            self.assertEqual(report["boot_mode"], "unexpected")
            self.assertEqual(report["overall_status"], "error")
            (root / "var/lib/kitpro-linux/kernel-state.json").write_text("{bad json\n")
            completed, report = self.status(root)
            self.assertEqual(completed.returncode, 2)
            assert report is not None
            self.assertFalse(report["metadata_consistency"])
        with tempfile.TemporaryDirectory() as name:
            completed, report = self.status(Path(name))
            self.assertEqual(completed.returncode, 2)
            assert report is not None
            self.assertIn("missing", report["errors"][0].lower())

    def test_space_preflight_root_and_esp_failures(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            completed, report = self.status(root, root_free=1)
            self.assertEqual(completed.returncode, 1)
            assert report is not None
            self.assertEqual(report["retention_preflight"]["result"], "insufficient-space")
            completed, report = self.status(root, esp_free=1)
            self.assertEqual(completed.returncode, 1)
            assert report is not None
            self.assertEqual(report["retention_preflight"]["result"], "insufficient-space")

    def test_status_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.fixture(root)
            self.transition(root)
            self.lifecycle(root, "record-successful-boot", running=B_RELEASE)
            before = self.evidence_hashes(root)
            completed, _report = self.status(root, running=B_RELEASE)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            after = self.evidence_hashes(root)
            self.assertEqual(after, before)

    def test_internal_failure_exit_code(self) -> None:
        environment = os.environ.copy()
        environment["KITPRO_KERNEL_LIFECYCLE"] = "/does/not/exist"
        completed = subprocess.run(
            [str(COMMAND), "--json"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
        )
        self.assertEqual(completed.returncode, 3)


if __name__ == "__main__":
    unittest.main()
