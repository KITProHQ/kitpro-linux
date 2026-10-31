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
        receipt = build_receipt(plan(), "2026-09-25T00:00:00Z", {"kind": "development-environment"})
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
        receipt = build_receipt(plan(), "2026-09-25T00:00:00Z", {"kind": "development-environment"})
        receipt["partitions"]["root_partuuid"] = "not-a-uuid"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "PARTUUID"):
            validate_receipt(receipt)

    def test_custom_storage_partuuids_are_recorded_additively(self) -> None:
        custom = plan()
        custom["partition_table"]["home"] = {
            "partition_uuid": "33333333-3333-4333-8333-333333333333"
        }
        custom["partition_table"]["swap"] = {
            "partition_uuid": "44444444-4444-4444-8444-444444444444"
        }
        receipt = build_receipt(custom, "2026-09-25T00:00:00Z", {"kind": "development-environment"})
        self.assertEqual(
            set(receipt["partitions"]),
            {"esp_partuuid", "root_partuuid", "home_partuuid", "swap_partuuid"},
        )
        validate_receipt(receipt)

    def test_reused_esp_records_the_dedicated_loader_without_secrets(self) -> None:
        preserved = plan()
        preserved["partition_table"].update(
            {
                "layout": "preserve",
                "esp": {
                    "partition_uuid": "11111111-1111-4111-8111-111111111111",
                    "action": "reuse",
                },
            }
        )
        receipt = build_receipt(
            preserved, "2026-09-25T00:00:00Z", {"kind": "development-environment"}
        )
        self.assertEqual(receipt["schema_version"], 5)
        self.assertEqual(
            receipt["preservation"]["bootloader_path"],
            "/EFI/KITPRO/kitpro-bootx64.efi",
        )
        validate_receipt(receipt)

        receipt["preservation"]["bootloader_path"] = "/EFI/BOOT/BOOTX64.EFI"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "EFI reuse evidence"):
            validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
