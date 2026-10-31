from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from kitpro_install_planner import (
    EncryptionRequestV1,
    StoragePlanningError,
    StorageRequestV3,
    plan_storage_v3,
)
from tools.install import engine
from tools.install.engine import render_repart_definitions
from tools.install.execution_commitment import AuthoritativeEngineCommitment
from tools.install.receipt import build_receipt, validate_receipt
from tools.install.render import fstab_from_plan
from tools.install.rootfs import _configure_encrypted_root, _configure_root_filesystem_modules

GIB = 1024**3


def encrypted_table(filesystem: str = "ext4") -> dict[str, object]:
    request = StorageRequestV3(
        filesystem=filesystem,
        layout="separate-home" if filesystem == "btrfs" else "standard",
        subvolumes=("@", "@home", "@snapshots") if filesystem == "btrfs" else (),
        compression="zstd" if filesystem == "btrfs" else "none",
    )
    table = plan_storage_v3(12 * GIB, request)
    for number, partition in enumerate(table["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{number:012d}"
        partition["planned_size_bytes"] = partition["size_bytes"]
    table.update({partition["role"]: partition for partition in table["partitions"]})
    table["encryption"] = {
        **request.encryption.to_dict(),
        "luks_uuid": "10000000-0000-4000-8000-000000000002",
        "partition_uuid": table["root"]["partition_uuid"],
    }
    return table


@pytest.mark.parametrize("filesystem", ["ext4", "btrfs"])
def test_encrypted_storage_is_deterministic_and_secret_free(filesystem: str) -> None:
    request = StorageRequestV3(
        filesystem=filesystem,
        subvolumes=("@",) if filesystem == "btrfs" else (),
        compression="zstd" if filesystem == "btrfs" else "none",
    )
    first = plan_storage_v3(12 * GIB, request)
    assert first == plan_storage_v3(12 * GIB, request)
    assert first["partitions"][1]["filesystem"] == "crypto_LUKS"
    assert first["partitions"][1]["inner_filesystem"] == filesystem
    assert "passphrase" not in json.dumps(first).lower()


@pytest.mark.parametrize(
    "storage_request,message",
    [
        (StorageRequestV3(layout="root-swap"), "swap"),
        (StorageRequestV3(layout="separate-home"), "encrypted ext4"),
        (StorageRequestV3(encryption=EncryptionRequestV1(mapper_name="unsafe")), "cryptroot"),
        (StorageRequestV3(encryption=EncryptionRequestV1(pbkdf="pbkdf2")), "key derivation"),
        (
            StorageRequestV3(encryption=EncryptionRequestV1(pbkdf_memory_kib=1048576)),
            "memory",
        ),
        (
            StorageRequestV3(encryption=EncryptionRequestV1(pbkdf_parallel_threads=8)),
            "parallelism",
        ),
        (StorageRequestV3(filesystem="xfs"), "ext4 or Btrfs"),
    ],
)
def test_invalid_encrypted_layouts_fail_closed(
    storage_request: StorageRequestV3, message: str
) -> None:
    with pytest.raises(StoragePlanningError, match=message):
        plan_storage_v3(12 * GIB, storage_request)


def test_encrypted_repart_fstab_initramfs_and_receipt_share_one_plan() -> None:
    table = encrypted_table("btrfs")
    plan = {
        "installer_version": "1.1.0.dev4",
        "release": "1.0",
        "repository_generation": "1.0-g0002",
        "install_spec_sha256": "1" * 64,
        "plan_sha256": "2" * 64,
        "repository": {"generation_manifest_sha256": "3" * 64},
        "partition_table": table,
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        definitions = render_repart_definitions(root, plan, populate=False)
        assert "Format=" not in (definitions / "10-root.conf").read_text()
        configured = root / "target"
        (configured / "etc").mkdir(parents=True)
        (configured / "usr/bin").mkdir(parents=True)
        (configured / "usr/bin/cryptsetup").touch()
        (configured / "usr/lib/initcpio/install").mkdir(parents=True)
        (configured / "usr/lib/initcpio/install/sd-encrypt").touch()
        (configured / "etc/mkinitcpio.conf").write_text(
            "MODULES=(virtio_pci virtio_blk ext4)\n"
            "HOOKS=(base systemd microcode modconf block filesystems fsck)\n"
        )
        _configure_root_filesystem_modules(configured, plan)
        _configure_encrypted_root(configured, plan)
        config = (configured / "etc/mkinitcpio.conf").read_text()
        assert "btrfs" in config and "sd-encrypt" in config and "keyboard" in config
        assert (
            table["encryption"]["luks_uuid"] in (configured / "etc/crypttab").read_text()
        )
        assert "x-initrd.attach" in (configured / "etc/crypttab").read_text()
    rendered = fstab_from_plan(plan)
    assert "/dev/mapper/cryptroot / btrfs subvol=@,compress=zstd 0 0" in rendered
    assert "/dev/mapper/cryptroot /home btrfs subvol=@home,compress=zstd 0 0" in rendered
    receipt = build_receipt(plan, "2026-10-27T00:00:00Z", {"kind": "development-environment"})
    validate_receipt(receipt)
    assert receipt["schema_version"] == 2
    assert receipt["encryption"]["mapper_name"] == "cryptroot"
    assert "passphrase" not in json.dumps(receipt).lower()


def test_typed_runtime_secret_bundle_is_read_from_a_sealed_descriptor() -> None:
    payload = b"kitpro-runtime-secrets-v1:" + json.dumps(
        {
            "schema_version": 1,
            "administrator_password": "administrator-secret",
            "luks_passphrase": "encryption-secret-phrase",
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    descriptor = os.memfd_create("kitpro-luks-test", os.MFD_CLOEXEC)
    try:
        os.write(descriptor, payload)
        assert AuthoritativeEngineCommitment._read_runtime_secrets(descriptor, True) == (
            "administrator-secret",
            "encryption-secret-phrase",
        )
    finally:
        os.close(descriptor)


def test_unformatted_encrypted_partition_is_accepted_before_luks_initialization() -> None:
    table = encrypted_table("ext4")
    inventory = {
        "blockdevices": [{
            "path": "/dev/qualification-only",
            "children": [
                {
                    "path": "/dev/qualification-only1",
                    "type": "part",
                    "partuuid": table["esp"]["partition_uuid"],
                    "fstype": "vfat",
                    "mountpoints": [None],
                },
                {
                    "path": "/dev/qualification-only2",
                    "type": "part",
                    "partuuid": table["root"]["partition_uuid"],
                    "fstype": None,
                    "mountpoints": [None],
                },
            ],
        }]
    }
    responses = [mock.Mock(stdout=""), mock.Mock(stdout=json.dumps(inventory))]
    with mock.patch.object(engine, "_recorded_command", side_effect=responses):
        devices = engine._planned_partition_devices(
            Path("/dev/qualification-only"), {"partition_table": table}, Path("/tmp")
        )
    assert devices["root"] == "/dev/qualification-only2"


def test_cryptsetup_receives_passphrase_only_on_standard_input() -> None:
    table = encrypted_table("ext4")
    plan = {"partition_table": table}
    passphrase = "not-present-in-command-arguments"
    with (
        mock.patch.object(
            engine,
            "_planned_partition_devices",
            return_value={"root": "/dev/qualification-only2"},
        ),
        mock.patch.object(engine, "_recorded_secret_command") as secret_command,
        mock.patch.object(engine, "_recorded_command") as recorded_command,
        engine.opened_encrypted_root(
            Path("/dev/qualification-only"), plan, Path("/tmp"), passphrase
        ) as mapper,
    ):
        assert mapper == Path("/dev/mapper/cryptroot")
    commands = [call.args[0] for call in secret_command.call_args_list]
    assert len(commands) == 2
    assert all(passphrase not in argument for command in commands for argument in command)
    assert all(command[command.index("--key-file") + 1] == "-" for command in commands)
    format_command = commands[0]
    assert format_command[format_command.index("--pbkdf-memory") + 1] == "262144"
    assert format_command[format_command.index("--pbkdf-parallel") + 1] == "2"
    assert recorded_command.call_args.args[0][0] == "mkfs.ext4"
