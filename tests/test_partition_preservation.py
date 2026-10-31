from __future__ import annotations

import pytest

from kitpro_install_planner import (
    ExistingPartitionV1,
    NewPartitionV1,
    StoragePlanningError,
    StorageRequestV7,
    plan_storage_v7,
    storage_request_from_dict,
)
from tools.install.model import parse_spec

MIB = 1024**2
GIB = 1024**3
ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
LINUX_TYPE = "0fc63daf-8483-4772-8e79-3d69d8477de4"


def request(*, root_filesystem: str = "ext4") -> StorageRequestV7:
    return StorageRequestV7(
        existing_partitions=(
            ExistingPartitionV1(
                1,
                MIB,
                260 * MIB,
                ESP_TYPE,
                "11111111-1111-1111-1111-111111111111",
                "vfat",
                "ESP-FS",
                "EXISTING-ESP",
                "reuse",
                "esp",
            ),
            ExistingPartitionV1(
                2,
                261 * MIB,
                2 * GIB,
                LINUX_TYPE,
                "22222222-2222-2222-2222-222222222222",
                "ext4",
                "DATA-FS",
                "KEEP",
            ),
        ),
        new_partitions=(NewPartitionV1("root", root_filesystem, "/", use_remaining=True),),
        subvolumes=("@", "@home") if root_filesystem == "btrfs" else (),
        compression="zstd" if root_filesystem == "btrfs" else "none",
    )


def test_preservation_plan_is_deterministic_and_keeps_existing_identity() -> None:
    first = plan_storage_v7(12 * GIB, request())
    second = plan_storage_v7(12 * GIB, request())
    assert first == second
    assert first["layout"] == "preserve"
    assert first["partitions"][0]["partition_uuid"].startswith("1111")
    assert first["partitions"][1]["action"] == "preserve"
    assert first["partitions"][2]["action"] == "create"
    assert first["partitions"][2]["start_bytes"] >= first["partitions"][1]["end_bytes"]


def test_btrfs_root_can_be_created_in_free_space() -> None:
    plan = plan_storage_v7(12 * GIB, request(root_filesystem="btrfs"))
    assert plan["filesystem"] == "btrfs"
    assert [item["name"] for item in plan["subvolumes"]] == ["@", "@home"]


@pytest.mark.parametrize("root_filesystem", ["ext4", "btrfs"])
def test_install_spec_accepts_preservation_storage_v7(root_filesystem: str) -> None:
    parsed = parse_spec(
        {
            "version": 1,
            "release": {"name": "1.0", "generation": "1.0-g0002"},
            "system": {"hostname": "kitpro"},
            "disk": {
                "device": "/dev/vda",
                "target_type": "block",
                "layout": "preserve",
                "filesystem": root_filesystem,
                "minimum_capacity_gib": 6,
                "storage": request(root_filesystem=root_filesystem).to_dict(),
            },
            "administrator": {"username": "kitpro-admin", "ssh_authorized_keys": []},
            "ssh": {"enabled": False},
        }
    )
    assert parsed.disk.layout == "preserve"
    assert isinstance(parsed.disk.storage, StorageRequestV7)


def test_explicit_existing_root_format_is_distinct_from_preserve() -> None:
    value = request().to_dict()
    value["existing_partitions"].append(
        {
            "number": 3,
            "start_bytes": 3 * GIB,
            "size_bytes": 6 * GIB,
            "partition_type": LINUX_TYPE,
            "partition_uuid": "33333333-3333-3333-3333-333333333333",
            "filesystem": "ext4",
            "filesystem_uuid": "OLD-ROOT",
            "label": "OLD",
            "action": "format",
            "role": "root",
            "format_as": "ext4",
        }
    )
    value["new_partitions"] = []
    parsed = storage_request_from_dict(value)
    plan = plan_storage_v7(12 * GIB, parsed)
    assert plan["preservation"]["formatted_partition_numbers"] == [3]
    assert plan["preservation"]["preserved_partition_numbers"] == [2]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["existing_partitions"].__setitem__(
            1, {**value["existing_partitions"][1], "start_bytes": 128 * MIB}
        ),
        lambda value: value["existing_partitions"][1].update(action="format", role=None),
        lambda value: value["existing_partitions"][0].update(action="preserve", role="esp"),
        lambda value: value.update(new_partitions=[]),
    ],
)
def test_unsafe_or_incomplete_preservation_requests_fail_closed(mutate) -> None:
    value = request().to_dict()
    mutate(value)
    with pytest.raises(StoragePlanningError):
        plan_storage_v7(12 * GIB, storage_request_from_dict(value))


def test_insufficient_contiguous_space_is_rejected_without_moving_partitions() -> None:
    value = request().to_dict()
    value["new_partitions"] = [
        {
            "role": "root",
            "filesystem": "ext4",
            "mount_point": "/",
            "size_bytes": 10 * GIB,
            "use_remaining": False,
        }
    ]
    with pytest.raises(StoragePlanningError, match="unallocated region"):
        plan_storage_v7(12 * GIB, storage_request_from_dict(value))
