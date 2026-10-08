from __future__ import annotations

import unittest
from pathlib import Path


SOURCE = (Path(__file__).resolve().parents[1] / "tools/phase84_acceptance.py").read_text()


class Phase84AcceptancePolicyTests(unittest.TestCase):
    def test_installed_matrix_covers_health_redaction_limits_and_manual_fallback(self) -> None:
        for marker in (
            'self.bundle("healthy", 0, "healthy")',
            'self.bundle("broken-firewall", 1, "error")',
            '"secret-redaction"',
            "rejected_text=CONTROLLED_SECRET",
            '"large-journal"',
            "require_truncated_journal=True",
            'self.bundle("manual-fallback", 1, "warning")',
            "kitpro-support-bundle verify",
            "iso_job.run()",
            'stage = "iso-to-disk-install"',
        ):
            self.assertIn(marker, SOURCE)

    def test_read_only_proof_hashes_managed_state(self) -> None:
        self.assertIn("support bundle changed managed installed state", SOURCE)
        self.assertIn("/var/lib/kitpro-linux /efi/loader/entries", SOURCE)
        self.assertIn("/etc/pacman.conf /var/lib/pacman/local /etc/systemd/network", SOURCE)
        self.assertIn("read_only_digest_before", SOURCE)
        self.assertIn("read_only_digest_after", SOURCE)

    def test_acceptance_is_local_tcg_and_uses_no_upload_path(self) -> None:
        self.assertIn('"acceleration": "tcg"', SOURCE)
        self.assertNotIn("curl", SOURCE)
        self.assertNotIn("requests.", SOURCE)
        self.assertNotIn("upload", SOURCE.lower())


if __name__ == "__main__":
    unittest.main()
