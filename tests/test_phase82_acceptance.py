from __future__ import annotations

import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "tools/phase82_acceptance.py").read_text()


class Phase82AcceptancePolicyTests(unittest.TestCase):
    def test_installed_matrix_covers_current_candidate_previous_and_degraded(self) -> None:
        for name in (
            "status-normal-current",
            "status-candidate-pending",
            "status-validated-current",
            "status-manual-fallback",
            "status-degraded-fallback",
        ):
            self.assertIn(name, SOURCE)

    def test_read_only_proof_hashes_installed_and_rescue_targets(self) -> None:
        self.assertIn("status-read-only-before", SOURCE)
        self.assertIn("status-read-only-after", SOURCE)
        self.assertIn("cmp /run/phase82-before.sha256 /run/phase82-after.sha256", SOURCE)
        self.assertIn("mount -o ro,nosuid,nodev", SOURCE)

    def test_rescue_uses_shared_kernel_status_command(self) -> None:
        self.assertIn("kitpro-rescue kernel-status", SOURCE)
        self.assertIn("boot_mode']=='unavailable", SOURCE)
        self.assertNotIn("repair-fallback-entry", SOURCE)
        self.assertNotIn("regenerate-previous-initramfs", SOURCE)


if __name__ == "__main__":
    unittest.main()
