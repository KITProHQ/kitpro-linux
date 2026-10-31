"""Deterministic storage observations shared by inventory safety tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from kitpro_install_planner.inventory import evaluate_storage_eligibility
from tools.install.disk import DiskState
from tools.install.model import ABSOLUTE_MINIMUM_BYTES


def disk_state(
    *,
    path: str = "/dev/sda",
    model: str = "KITPro Fixture Disk",
    serial: str | None = "KITPRO-SATA-001",
    wwn: str | None = None,
    stable_ids: tuple[str, ...] = (),
    size_bytes: int = 16 * 1024**3,
    transport: str | None = "sata",
    read_only: bool | None = False,
    mounted_paths: tuple[str, ...] = (),
    protection_reasons: tuple[str, ...] = (),
    observation_errors: tuple[str, ...] = (),
    partitions: tuple[dict[str, Any], ...] = (),
    duplicate_tokens: frozenset[str] = frozenset(),
) -> DiskState:
    identity = {
        "model": model,
        "serial": serial,
        "wwn": wwn,
        "stable_ids": list(stable_ids),
    }
    state = DiskState(
        path=path,
        target_type="block",
        size_bytes=size_bytes,
        identity=identity,
        mounted_paths=mounted_paths,
        signatures=(),
        partition_table="gpt" if partitions else "unknown",
        marker_sha256=None,
        partitions=partitions,
        transport=transport,
        read_only=read_only,
        stable_ids=stable_ids,
        protection_reasons=protection_reasons,
        observation_errors=observation_errors,
    )
    eligibility = evaluate_storage_eligibility(
        target_type="block",
        device_type="disk",
        size_bytes=size_bytes,
        minimum_capacity_bytes=ABSOLUTE_MINIMUM_BYTES,
        identity=identity,
        mounted_paths=mounted_paths,
        read_only=read_only,
        protection_reasons=protection_reasons,
        observation_errors=observation_errors,
        duplicate_tokens=duplicate_tokens,
    )
    return replace(state, eligibility=eligibility)


EFI_PARTITION = (
    {
        "path": "/dev/sda1",
        "number": 1,
        "start_bytes": 1024**2,
        "size_bytes": 512 * 1024**2,
        "partition_type": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "partition_uuid": "11111111-1111-1111-1111-111111111111",
        "filesystem": "vfat",
        "filesystem_uuid": "EFI-0001",
        "filesystem_label": "EFI",
        "partition_label": "EFI System",
        "mount_points": (),
    },
)
