from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools import kitpro_repo
from tools.install.receipt import build_receipt, load_source_metadata, validate_receipt


def plan() -> dict[str, object]:
    return {
        "installer_version": "0.3.0-dev.1",
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


class InstallReceiptTests(unittest.TestCase):
    def test_development_receipt_is_valid(self) -> None:
        receipt = build_receipt(
            plan(), "2026-09-25T00:00:00Z", {"kind": "development-environment"}
        )
        validate_receipt(receipt)
        self.assertEqual(receipt["installation_source"]["kind"], "development-environment")

    def test_developer_iso_metadata_is_strict(self) -> None:
        metadata = {
            "kind": "developer-iso",
            "media_version": "0.4.0-dev.1",
            "source_git_commit": "1" * 40,
            "profile_sha256": "2" * 64,
            "build_configuration_sha256": "3" * 64,
        }
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "source.json"
            kitpro_repo.atomic_write_json(path, metadata)
            self.assertEqual(load_source_metadata(path), metadata)
            metadata["extra"] = "not allowed"
            kitpro_repo.atomic_write_json(path, metadata)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported fields"):
                load_source_metadata(path)

    def test_invalid_partuuid_is_rejected(self) -> None:
        receipt = build_receipt(
            plan(), "2026-09-25T00:00:00Z", {"kind": "development-environment"}
        )
        receipt["partitions"]["root_partuuid"] = "not-a-uuid"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "PARTUUID"):
            validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
