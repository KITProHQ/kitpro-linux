from __future__ import annotations

from dataclasses import replace

import pytest

from kitpro_install_planner.inventory import (
    StorageRejection,
    duplicate_identity_tokens,
    stable_identity_tokens,
)
from tests.storage_inventory_fixtures import EFI_PARTITION, disk_state
from tools import kitpro_repo
from tools.install.disk import assert_disk_unchanged


@pytest.mark.parametrize(
    ("path", "transport", "serial", "wwn"),
    [
        ("/dev/sda", "sata", "SATA-001", None),
        ("/dev/nvme0n1", "nvme", "NVME-001", "eui.0001"),
        ("/dev/vda", "virtio", "VIRTIO-001", None),
    ],
)
def test_supported_transport_observations_are_typed_and_eligible(
    path: str, transport: str, serial: str, wwn: str | None
) -> None:
    observed = disk_state(path=path, transport=transport, serial=serial, wwn=wwn)

    assert observed.transport == transport
    assert observed.read_only is False
    assert observed.eligibility.eligible
    assert observed.eligibility.requires_destructive_confirmation


def test_multiple_disks_with_distinct_identity_are_unambiguous() -> None:
    identities = [
        disk_state(path="/dev/sda", serial="SATA-001").identity,
        disk_state(path="/dev/nvme0n1", serial="NVME-001").identity,
        disk_state(path="/dev/vda", serial="VIRTIO-001").identity,
    ]

    assert duplicate_identity_tokens(identities) == frozenset()


def test_duplicate_stable_identity_is_rejected() -> None:
    first = disk_state(path="/dev/sda", serial="DUPLICATE")
    second = disk_state(path="/dev/sdb", serial="DUPLICATE")
    duplicates = duplicate_identity_tokens([first.identity, second.identity])
    observed = disk_state(path="/dev/sda", serial="DUPLICATE", duplicate_tokens=duplicates)

    assert duplicates == frozenset({"serial:duplicate"})
    assert observed.eligibility.rejection_reasons == (StorageRejection.DUPLICATE_STABLE_IDENTITY,)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"read_only": True}, StorageRejection.READ_ONLY),
        ({"read_only": None}, StorageRejection.READ_ONLY_UNKNOWN),
        ({"serial": None}, StorageRejection.MISSING_STABLE_IDENTITY),
        ({"mounted_paths": ("/mnt/data",)}, StorageRejection.MOUNTED),
        (
            {"protection_reasons": (StorageRejection.INSTALLATION_MEDIA,)},
            StorageRejection.INSTALLATION_MEDIA,
        ),
        (
            {"protection_reasons": (StorageRejection.RUNNING_SYSTEM,)},
            StorageRejection.RUNNING_SYSTEM,
        ),
        ({"observation_errors": ("wipefs failed",)}, StorageRejection.INCOMPLETE_OBSERVATION),
    ],
)
def test_fail_closed_rejection_reasons_are_explicit(changes: dict, reason: str) -> None:
    observed = disk_state(**changes)

    assert not observed.eligibility.eligible
    assert reason in observed.eligibility.rejection_reasons
    assert not observed.eligibility.requires_destructive_confirmation


def test_stable_by_id_alias_can_establish_identity_when_serial_and_wwn_are_missing() -> None:
    observed = disk_state(
        serial=None,
        wwn=None,
        stable_ids=("ata-KITPro_Fixture_001",),
    )

    assert stable_identity_tokens(observed.identity) == ("by-id:ata-kitpro_fixture_001",)
    assert observed.eligibility.eligible


def test_existing_partitions_and_efi_reuse_remain_eligible() -> None:
    observed = disk_state(partitions=EFI_PARTITION)

    assert observed.partition_table == "gpt"
    assert observed.partitions[0]["filesystem"] == "vfat"
    assert observed.eligibility.eligible


@pytest.mark.parametrize(
    "changed",
    [
        disk_state(size_bytes=20 * 1024**3),
        disk_state(serial="REPLACEMENT-DISK"),
        disk_state(read_only=True),
    ],
)
def test_changed_or_stale_plan_observation_is_rejected(changed) -> None:
    planned = disk_state()

    with pytest.raises(kitpro_repo.PipelineError, match="changed after planning"):
        assert_disk_unchanged(planned.to_dict(), changed)


def test_identical_fresh_observation_satisfies_plan_binding() -> None:
    observed = disk_state()

    assert_disk_unchanged(observed.to_dict(), replace(observed))
