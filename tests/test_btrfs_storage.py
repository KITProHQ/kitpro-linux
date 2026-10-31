from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from kitpro_install_planner import (
    StoragePlanningError,
    StorageRequestV1,
    StorageRequestV2,
    plan_storage_v1,
    plan_storage_v2,
)
from tools.install.engine import render_repart_definitions
from tools.install import engine
from tools.install.model import parse_spec
from tools.install.render import fstab_from_plan, loader_entry
from tools.install.rootfs import _configure_root_filesystem_modules
from tools.kitpro_repo import PipelineError

GIB = 1024**3


@pytest.mark.parametrize(
    ("layout", "subvolumes", "swap"),
    [
        ("standard", ("@",), False),
        ("separate-home", ("@", "@home"), False),
        ("root-swap", ("@",), True),
        ("root-home-swap", ("@", "@home", "@snapshots"), True),
    ],
)
def test_btrfs_layouts_are_deterministic_and_share_one_filesystem(
    layout: str, subvolumes: tuple[str, ...], swap: bool
) -> None:
    request = StorageRequestV2(
        layout=layout,
        swap_size_bytes=GIB if swap else None,
        subvolumes=subvolumes,
        compression="zstd",
    )
    first = plan_storage_v2(12 * GIB, request)
    assert first == plan_storage_v2(12 * GIB, request)
    assert [item["role"] for item in first["partitions"]] == (
        ["esp", "root", "swap"] if swap else ["esp", "root"]
    )
    assert first["partitions"][1]["filesystem"] == "btrfs"
    assert first["subvolumes"] == [
        {
            "name": name,
            "mount_point": {"@": "/", "@home": "/home", "@snapshots": "/.snapshots"}[name],
        }
        for name in subvolumes
    ]


@pytest.mark.parametrize(
    ("storage_request", "message"),
    [
        (StorageRequestV2(subvolumes=("@home",)), "root subvolume"),
        (StorageRequestV2(subvolumes=("@", "@")), "unique"),
        (StorageRequestV2(subvolumes=("@", "unsafe")), "unsupported"),
        (StorageRequestV2(compression="lzo"), "compression"),
        (StorageRequestV2(root_size_bytes=6 * GIB), "share"),
        (StorageRequestV2(layout="separate-home", subvolumes=("@",)), "@home"),
    ],
)
def test_invalid_btrfs_requests_fail_closed(
    storage_request: StorageRequestV2, message: str
) -> None:
    with pytest.raises(StoragePlanningError, match=message):
        plan_storage_v2(12 * GIB, storage_request)


def test_ext4_v1_plan_is_unchanged() -> None:
    first = plan_storage_v1(12 * GIB, StorageRequestV1())
    assert first["schema_version"] == 1
    assert first["partitions"][1]["filesystem"] == "ext4"
    assert "subvolumes" not in first


def test_btrfs_repart_fstab_and_boot_flags_share_the_authoritative_plan() -> None:
    table = plan_storage_v2(
        12 * GIB,
        StorageRequestV2(
            layout="root-home-swap",
            swap_size_bytes=GIB,
            subvolumes=("@", "@home", "@snapshots"),
        ),
    )
    for number, partition in enumerate(table["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{number:012d}"
        partition["planned_size_bytes"] = partition["size_bytes"]
    table.update({partition["role"]: partition for partition in table["partitions"]})
    plan = {"partition_table": table}
    with tempfile.TemporaryDirectory() as directory:
        definitions = render_repart_definitions(Path(directory), plan, populate=False)
        assert "Format=btrfs" in (definitions / "10-root.conf").read_text()
        assert not (definitions / "20-home.conf").exists()
        assert "Format=swap" in (definitions / "30-swap.conf").read_text()
    rendered = fstab_from_plan(plan)
    root_uuid = table["root"]["partition_uuid"]
    assert f"PARTUUID={root_uuid} / btrfs subvol=@,compress=zstd 0 0" in rendered
    assert f"PARTUUID={root_uuid} /home btrfs subvol=@home,compress=zstd 0 0" in rendered
    assert f"PARTUUID={root_uuid} /.snapshots btrfs subvol=@snapshots,compress=zstd 0 0" in rendered
    assert "rootflags=subvol=@,compress=zstd" in loader_entry(
        root_uuid, root_flags="subvol=@,compress=zstd"
    )


def test_install_spec_v1_accepts_only_the_versioned_btrfs_extension() -> None:
    document = {
        "version": 1,
        "release": {"name": "0.1-dev", "generation": "0.1-dev-g0002"},
        "system": {"hostname": "kitpro", "locale": "C.UTF-8", "timezone": "UTC"},
        "disk": {
            "device": "/dev/vda",
            "target_type": "block",
            "layout": "separate-home",
            "filesystem": "btrfs",
            "minimum_capacity_gib": 12,
            "storage": StorageRequestV2(
                layout="separate-home", subvolumes=("@", "@home")
            ).to_dict(),
        },
        "network": {"mode": "dhcp"},
        "administrator": {"username": "kitpro-admin", "ssh_authorized_keys": []},
        "ssh": {"enabled": False},
        "firewall": {"ssh": False},
        "boot": {"mode": "uefi"},
    }
    parsed = parse_spec(document)
    assert isinstance(parsed.disk.storage, StorageRequestV2)
    broken = {**document, "disk": {**document["disk"], "storage": None}}
    with pytest.raises(PipelineError, match="schema version 2"):
        parse_spec(broken)


def test_btrfs_plan_adds_the_required_initramfs_module_without_changing_ext4() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        config = root / "etc/mkinitcpio.conf"
        config.parent.mkdir(parents=True)
        config.write_text(
            "MODULES=(virtio_pci virtio_blk ext4)\nHOOKS=(base systemd block filesystems)\n"
        )
        btrfs_plan = {"partition_table": {"root": {"filesystem": "btrfs"}}}
        _configure_root_filesystem_modules(root, btrfs_plan)
        assert "MODULES=(virtio_pci virtio_blk ext4 btrfs)" in config.read_text()
        ext4_plan = {"partition_table": {"root": {"filesystem": "ext4"}}}
        before = config.read_text()
        _configure_root_filesystem_modules(root, ext4_plan)
        assert config.read_text() == before


def test_btrfs_mounts_planned_subvolumes_and_cleans_up_in_reverse_order() -> None:
    table = plan_storage_v2(
        12 * GIB,
        StorageRequestV2(
            layout="separate-home",
            subvolumes=("@", "@home", "@snapshots"),
            compression="zstd",
        ),
    )
    children = []
    for number, partition in enumerate(table["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{number:012d}"
        children.append(
            {
                "path": f"/dev/qualification-only{number}",
                "type": "part",
                "partuuid": partition["partition_uuid"],
                "fstype": partition["filesystem"],
                "mountpoints": [None],
            }
        )
    table.update({partition["role"]: partition for partition in table["partitions"]})
    plan = {"plan_sha256": "a" * 64, "partition_table": table}
    inventory = mock.Mock(
        stdout=json.dumps(
            {"blockdevices": [{"path": "/dev/qualification-only", "children": children}]}
        )
    )
    calls: list[list[str]] = []

    def record(command: list[str], *_args: object) -> mock.Mock:
        calls.append(command)
        return inventory if command[0] == "lsblk" else mock.Mock(stdout="")

    with (
        tempfile.TemporaryDirectory() as directory,
        mock.patch.object(engine, "_recorded_command", side_effect=record),
        mock.patch.object(engine, "INSTALL_MOUNT_ROOT", Path(directory) / "mounts"),
    ):
        with engine.mounted_install_target(
            Path("/dev/qualification-only"), plan, Path(directory)
        ) as root:
            assert root.name == "a" * 16

    assert any(command[:3] == ["mount", "-o", "subvolid=5"] for command in calls)
    assert [command[:3] for command in calls if command[:3] == ["btrfs", "subvolume", "create"]]
    mount_options = [command[2] for command in calls if command[:2] == ["mount", "-o"]]
    assert "subvol=@,compress=zstd" in mount_options
    assert "subvol=@home,compress=zstd" in mount_options
    assert "subvol=@snapshots,compress=zstd" in mount_options
    unmounts = [command[1] for command in calls if command[0] == "umount"]
    assert unmounts[-3].endswith("/.snapshots")
    assert unmounts[-2].endswith("/home")
    assert unmounts[-1].endswith("/" + "a" * 16)
