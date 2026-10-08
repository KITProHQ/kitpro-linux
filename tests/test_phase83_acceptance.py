from __future__ import annotations

import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "tools/phase83_acceptance.py").read_text()


class Phase83AcceptancePolicyTests(unittest.TestCase):
    def test_installed_matrix_covers_required_health_states(self) -> None:
        for name in (
            "health-baseline",
            "health-broken-nftables",
            "health-broken-repository",
            "health-low-space",
            "health-candidate",
            "health-manual-fallback",
            "health-final",
        ):
            self.assertIn(name, SOURCE)

    def test_read_only_proof_hashes_installed_and_rescue_targets(self) -> None:
        self.assertIn("health-read-only-before", SOURCE)
        self.assertIn("health-read-only-after", SOURCE)
        self.assertIn("cmp /run/phase83-before.sha256 /run/phase83-after.sha256", SOURCE)
        self.assertIn("mount -o ro,nosuid,nodev", SOURCE)

    def test_rescue_uses_shared_health_command_and_offline_semantics(self) -> None:
        self.assertIn("kitpro-rescue health", SOURCE)
        self.assertIn("d['mode']=='offline'", SOURCE)
        self.assertIn("state']=='unavailable'", SOURCE)
        self.assertNotIn("repair-boot", SOURCE)
        self.assertNotIn("regenerate-initramfs", SOURCE)


if __name__ == "__main__":
    unittest.main()
