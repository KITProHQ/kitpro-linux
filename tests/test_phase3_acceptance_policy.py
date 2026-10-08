from __future__ import annotations

import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "tools/phase3_acceptance.py").read_text()


class Phase3AcceptancePolicyTests(unittest.TestCase):
    def test_serial_handoff_accepts_durable_kernel_validation_marker(self) -> None:
        self.assertIn('"KITPRO_KERNEL_BOOT_OK" in content', SOURCE)
        self.assertIn('"Multi-User System" in content', SOURCE)
        self.assertIn("systemctl is-active multi-user.target", SOURCE)


if __name__ == "__main__":
    unittest.main()
