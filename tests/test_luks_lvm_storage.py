from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from kitpro_install_planner import (
    EncryptionRequestV1,
    LogicalVolumeV1,
    StorageRequestV6,
    plan_storage_v6,
)
from tools.install import engine
from tools.install.receipt import build_receipt, validate_receipt
from tools.install.render import fstab_from_plan
from tools.install.rootfs import _configure_encrypted_root, _configure_lvm_root

MIB = 1024**2
GIB = 1024**3


def request(*, mapper: str = "cryptlvm") -> StorageRequestV6:
    return StorageRequestV6(
        logical_volumes=(
            LogicalVolumeV1("root", "root", "ext4", "/", 6 * GIB),
            LogicalVolumeV1("home", "home", "ext4", "/home", 2 * GIB),
            LogicalVolumeV1("swap", "swap", "swap", None, GIB),
        ),
        encryption=EncryptionRequestV1(mapper_name=mapper),
    )


def test_luks_lvm_plan_is_deterministic_and_accounts_for_container_metadata() -> None:
    first = plan_storage_v6(12 * GIB, request())
    assert first == plan_storage_v6(12 * GIB, request())
    assert first["schema_version"] == 6
    assert first["partitions"][1]["filesystem"] == "crypto_LUKS"
    assert first["partitions"][1]["inner_filesystem"] == "LVM2_member"
    assert first["encryption"]["mapper_name"] == "cryptlvm"
    assert first["lvm"]["container_overhead_bytes"] == 16 * MIB
    assert (
        first["lvm"]["total_extents"]
        == (first["partitions"][1]["size_bytes"] - 16 * MIB) // first["lvm"]["extent_size_bytes"]
    )


def test_luks_lvm_fstab_keeps_all_data_and_swap_on_logical_volumes() -> None:
    plan = plan_storage_v6(12 * GIB, request())
    for index, partition in enumerate(plan["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{index:012d}"
    table = {
        **plan,
        **{item["role"]: item for item in plan["partitions"]},
        **{item["role"]: item for item in plan["lvm"]["logical_volumes"]},
    }
    rendered = fstab_from_plan({"partition_table": table})
    assert "/dev/mapper/vgkitpro-root / ext4 defaults 0 1" in rendered
    assert "/dev/mapper/vgkitpro-home /home ext4 defaults 0 2" in rendered
    assert "/dev/mapper/vgkitpro-swap none swap defaults 0 0" in rendered
    assert "cryptlvm" not in rendered


def combined_plan() -> dict[str, object]:
    table = plan_storage_v6(12 * GIB, request())
    for index, partition in enumerate(table["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{index:012d}"
        partition["planned_size_bytes"] = partition["size_bytes"]
    table.update({item["role"]: item for item in table["partitions"]})
    table.update({item["role"]: item for item in table["lvm"]["logical_volumes"]})
    table["storage_schema_version"] = 6
    table["encryption"] = {
        **table["encryption"],
        "partition_uuid": table["lvm-pv"]["partition_uuid"],
        "luks_uuid": "10000000-0000-4000-8000-000000000002",
    }
    return {
        "installer_version": "1.1.0.dev7",
        "release": "1.0",
        "repository_generation": "1.0-g0002",
        "install_spec_sha256": "1" * 64,
        "plan_sha256": "2" * 64,
        "repository": {"generation_manifest_sha256": "3" * 64},
        "partition_table": table,
        "boot": {
            "encrypted_root": True,
            "luks_uuid": table["encryption"]["luks_uuid"],
            "lvm_root": "vgkitpro/root",
        },
    }


def test_luks_lvm_receipt_records_both_layers_without_secrets() -> None:
    receipt = build_receipt(
        combined_plan(), "2026-10-27T00:00:00Z", {"kind": "development-environment"}
    )
    validate_receipt(receipt)
    assert receipt["schema_version"] == 4
    assert receipt["encryption"]["mapper_name"] == "cryptlvm"
    assert receipt["lvm"]["physical_volume_partuuid"] == receipt["partitions"]["lvm_pv_partuuid"]
    assert "passphrase" not in json.dumps(receipt).lower()


def test_luks_lvm_initramfs_unlocks_before_lvm_activation(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True)
    (root / "usr/bin/cryptsetup").touch()
    (root / "usr/bin/lvm").touch()
    (root / "usr/lib/initcpio/install").mkdir(parents=True)
    (root / "usr/lib/initcpio/install/sd-encrypt").touch()
    (root / "usr/lib/initcpio/install/lvm2").touch()
    (root / "etc/mkinitcpio.conf").write_text(
        "MODULES=(virtio_pci virtio_blk ext4)\n"
        "HOOKS=(base systemd microcode modconf block filesystems fsck)\n"
    )
    plan = combined_plan()
    _configure_encrypted_root(root, plan)
    _configure_lvm_root(root, plan)
    hooks = (root / "etc/mkinitcpio.conf").read_text().split("HOOKS=(", 1)[1].split(")", 1)[0]
    assert hooks.split().index("sd-encrypt") < hooks.split().index("lvm2")


def test_encrypted_mapper_is_not_formatted_before_becoming_the_lvm_pv() -> None:
    plan = combined_plan()
    with (
        mock.patch.object(
            engine,
            "_planned_partition_devices",
            return_value={"lvm-pv": "/dev/qualification-only2"},
        ),
        mock.patch.object(engine, "_recorded_secret_command") as secret_command,
        mock.patch.object(engine, "_recorded_command") as recorded_command,
        engine.opened_encrypted_root(
            Path("/dev/qualification-only"), plan, Path("/tmp"), "qualified-passphrase"
        ) as mapper,
    ):
        assert mapper == Path("/dev/mapper/cryptlvm")
    assert len(secret_command.call_args_list) == 2
    assert all(not call.args[0][0].startswith("mkfs") for call in recorded_command.call_args_list)


def test_luks_lvm_repart_definitions_create_an_unformatted_encrypted_pv(
    tmp_path: Path,
) -> None:
    definitions = engine.render_repart_definitions(
        tmp_path / "definitions", combined_plan(), populate=False
    )
    esp = (definitions / "00-esp.conf").read_text()
    encrypted_pv = (definitions / "10-lvm-pv.conf").read_text()

    assert "Format=vfat" in esp
    assert "Type=linux-generic" in encrypted_pv
    assert "Format=" not in encrypted_pv
    assert "SizeMinBytes=" in encrypted_pv
    assert "SizeMaxBytes=" in encrypted_pv
