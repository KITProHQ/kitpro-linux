from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from kitpro_install_planner import (
    LogicalVolumeV1,
    StoragePlanningError,
    StorageRequestV5,
    plan_storage_v5,
)
from tools import kitpro_repo
from tools.install import rootfs
from tools.install.render import fstab_from_plan

MIB = 1024**2
GIB = 1024**3


def lv(
    name: str,
    role: str,
    filesystem: str,
    mount: str | None,
    size: int | None = None,
    *,
    remaining: bool = False,
) -> LogicalVolumeV1:
    return LogicalVolumeV1(name, role, filesystem, mount, size, remaining)


def test_lvm_plan_is_deterministic_extent_aligned_and_can_leave_free_space() -> None:
    request = StorageRequestV5(
        volume_group="vgkitpro",
        logical_volumes=(
            lv("root", "root", "ext4", "/", 6 * GIB),
            lv("home", "home", "ext4", "/home", 2 * GIB),
        ),
    )
    first = plan_storage_v5(12 * GIB, request)
    assert first == plan_storage_v5(12 * GIB, request)
    assert first["alignment_bytes"] == MIB
    assert first["partitions"][0]["start_bytes"] == MIB
    assert [item["role"] for item in first["partitions"]] == ["esp", "lvm-pv"]
    assert first["lvm"]["volume_group"] == "vgkitpro"
    assert first["lvm"]["free_extents"] > 0
    assert all(
        item["size_bytes"] % first["lvm"]["extent_size_bytes"] == 0
        for item in first["lvm"]["logical_volumes"]
    )


def test_lvm_remaining_space_and_swap_plan() -> None:
    plan = plan_storage_v5(
        12 * GIB,
        StorageRequestV5(
            logical_volumes=(
                lv("root", "root", "ext4", "/", 7 * GIB),
                lv("swap", "swap", "swap", None, GIB),
                lv("home", "home", "ext4", "/home", remaining=True),
            )
        ),
    )
    assert plan["lvm"]["free_extents"] == 0
    assert plan["lvm"]["logical_volumes"][-1]["size_policy"] == "remaining"


@pytest.mark.parametrize(
    ("storage_request", "message"),
    [
        (StorageRequestV5(), "requires logical volumes"),
        (
            StorageRequestV5(logical_volumes=(lv("home", "home", "ext4", "/home", GIB),)),
            "exactly one root",
        ),
        (
            StorageRequestV5(
                logical_volumes=(
                    lv("root", "root", "ext4", "/", 6 * GIB),
                    lv("root", "home", "ext4", "/home", GIB),
                )
            ),
            "names must be unique",
        ),
        (
            StorageRequestV5(
                logical_volumes=(
                    lv("root", "root", "ext4", "/", remaining=True),
                    lv("swap", "swap", "swap", None, GIB),
                )
            ),
            "must be last",
        ),
        (
            StorageRequestV5(logical_volumes=(lv("root", "root", "btrfs", "/", 6 * GIB),)),
            "unsupported root",
        ),
        (
            StorageRequestV5(
                volume_group="bad-name",
                logical_volumes=(lv("root", "root", "ext4", "/", 6 * GIB),),
            ),
            "volume group name",
        ),
    ],
)
def test_invalid_lvm_plans_fail_closed(storage_request: StorageRequestV5, message: str) -> None:
    with pytest.raises(StoragePlanningError, match=message):
        plan_storage_v5(12 * GIB, storage_request)


def test_lvm_fstab_uses_mapper_devices() -> None:
    plan = plan_storage_v5(
        12 * GIB,
        StorageRequestV5(
            logical_volumes=(
                lv("root", "root", "ext4", "/", 6 * GIB),
                lv("var", "var", "ext4", "/var", GIB),
                lv("swap", "swap", "swap", None, GIB),
            )
        ),
    )
    for index, partition in enumerate(plan["partitions"], 1):
        partition["partition_uuid"] = f"00000000-0000-4000-8000-{index:012d}"
    table = {
        **plan,
        **{item["role"]: item for item in plan["partitions"]},
        **{item["role"]: item for item in plan["lvm"]["logical_volumes"]},
    }
    rendered = fstab_from_plan({"partition_table": table})
    assert "/dev/mapper/vgkitpro-root / ext4 defaults 0 1" in rendered
    assert "/dev/mapper/vgkitpro-var /var ext4 defaults 0 2" in rendered
    assert "/dev/mapper/vgkitpro-swap none swap defaults 0 0" in rendered


def test_lvm_boot_validation_uses_mapper_without_evaluating_partition_fallback() -> None:
    plan = {
        "boot": {"root_identifier": "/dev/mapper/vgkitpro-root"},
        "partition_table": {"root": {"mapper_path": "/dev/mapper/vgkitpro-root"}},
    }

    assert rootfs._planned_root_identifier(plan) == "/dev/mapper/vgkitpro-root"


def test_lvm_metadata_reserves_at_least_one_extent() -> None:
    plan = plan_storage_v5(
        12 * GIB,
        StorageRequestV5(
            extent_size_bytes=4 * MIB,
            logical_volumes=(lv("root", "root", "ext4", "/", remaining=True),),
        ),
    )
    assert plan["lvm"]["total_extents"] - plan["lvm"]["usable_extents"] == 1


def test_lvm_target_packages_are_hash_verified_and_installed_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_root = tmp_path / "target-packages"
    package_root.mkdir()
    packages: dict[str, str] = {}
    for name in ("libaio.pkg.tar.zst", "thin.pkg.tar.zst", "lvm2.pkg.tar.zst"):
        content = name.encode()
        (package_root / name).write_bytes(content)
        packages[name] = hashlib.sha256(content).hexdigest()
    kitpro_repo.atomic_write_json(
        package_root / "manifest.json",
        {"schema_version": 1, "packages": packages},
    )
    target = tmp_path / "root"
    (target / "var/lib/pacman").mkdir(parents=True)
    (target / "etc").mkdir()
    (target / "etc/pacman.conf").write_text("[options]\n")
    commands: list[list[str]] = []
    monkeypatch.setattr(rootfs, "TARGET_LVM_PACKAGES", package_root)
    monkeypatch.setattr(rootfs.kitpro_phase2, "run", lambda command: commands.append(command))

    count = rootfs._install_lvm_target_packages(target, {"partition_table": {"lvm": {}}})

    assert count == 3
    assert commands[0][0] == "pacman"
    assert "-U" in commands[0]
    assert commands[0][commands[0].index("--config") + 1] == str(target / "etc/pacman.conf")
    assert commands[0][commands[0].index("--gpgdir") + 1] == str(target / "etc/pacman.d/gnupg")
    assert all(str(package_root) in item for item in commands[0][-3:])
