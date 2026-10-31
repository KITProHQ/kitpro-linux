"""Read-only disk discovery and fail-closed target checks."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from kitpro_install_planner.inventory import (
    StorageEligibility,
    StorageRejection,
    duplicate_identity_tokens,
    evaluate_storage_eligibility,
    rejection_message,
)
from tools import kitpro_repo
from tools.install.model import ABSOLUTE_MINIMUM_BYTES

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DISK_ROOT = PROJECT_ROOT / ".state/phase3/test-disks"
DEV_DISK_BY_ID = Path("/dev/disk/by-id")


@dataclass(frozen=True)
class DiskState:
    path: str
    target_type: str
    size_bytes: int
    identity: dict[str, Any]
    mounted_paths: tuple[str, ...]
    signatures: tuple[dict[str, Any], ...]
    partition_table: str
    marker_sha256: str | None
    partitions: tuple[dict[str, Any], ...] = ()
    transport: str | None = None
    read_only: bool | None = False
    stable_ids: tuple[str, ...] = ()
    protection_reasons: tuple[str, ...] = ()
    observation_errors: tuple[str, ...] = ()
    eligibility: StorageEligibility = field(
        default_factory=lambda: StorageEligibility(True, True, ())
    )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["mounted_paths"] = list(self.mounted_paths)
        value["signatures"] = list(self.signatures)
        value["partitions"] = [
            {**item, "mount_points": list(item.get("mount_points", ()))} for item in self.partitions
        ]
        value["stable_ids"] = list(self.stable_ids)
        value["protection_reasons"] = list(self.protection_reasons)
        value["observation_errors"] = list(self.observation_errors)
        value["eligibility"] = self.eligibility.to_dict()
        return value


def marker_path(target: Path) -> Path:
    return target.with_name(target.name + ".kitpro-test-disk.json")


def create_test_disk(target: Path, size_bytes: int) -> dict[str, Any]:
    if not target.is_absolute():
        raise kitpro_repo.PipelineError("test disk path must be absolute")
    if size_bytes < ABSOLUTE_MINIMUM_BYTES:
        raise kitpro_repo.PipelineError("test disk is smaller than the installer absolute minimum")
    if target.exists() or marker_path(target).exists():
        raise kitpro_repo.PipelineError(
            f"refusing to replace existing test disk or marker: {target}"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.ftruncate(descriptor, size_bytes)
    finally:
        os.close(descriptor)
    marker = {
        "schema_version": 1,
        "purpose": "KITPro Linux Phase 3 disposable test disk",
        "path": str(target.resolve()),
        "size_bytes": size_bytes,
    }
    kitpro_repo.atomic_write_json(marker_path(target), marker)
    return marker


def _command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def _signatures(path: Path) -> tuple[dict[str, Any], ...]:
    completed = _command(
        ["wipefs", "--json", "--output", "DEVICE,OFFSET,TYPE,UUID,LABEL", str(path)]
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"cannot inspect signatures on {path}: {completed.stderr.strip()}"
        )
    document = json.loads(completed.stdout or "{}")
    signatures = document.get("signatures", [])
    if not isinstance(signatures, list):
        raise kitpro_repo.PipelineError(
            f"wipefs returned an invalid signature inventory for {path}"
        )
    return tuple(
        sorted(signatures, key=lambda item: (str(item.get("offset")), str(item.get("type"))))
    )


def _partition_table(path: Path) -> str:
    completed = _command(["parted", "-sm", str(path), "unit", "B", "print"])
    lines = [line for line in completed.stdout.splitlines() if not line.startswith("Error:")]
    if not lines:
        return "unknown"
    device = next((line for line in lines if line.startswith(str(path) + ":")), "")
    fields = device.split(":")
    return fields[5] if len(fields) > 5 and fields[5] else "unknown"


def _loop_mounts(path: Path) -> tuple[str, ...]:
    completed = _command(["losetup", "-j", str(path)])
    loops = [line.split(":", 1)[0] for line in completed.stdout.splitlines() if ":" in line]
    mounts: set[str] = set()
    for loop in loops:
        result = _command(["lsblk", "-J", "-o", "MOUNTPOINTS", loop])
        if result.returncode != 0:
            continue
        for device in json.loads(result.stdout).get("blockdevices", []):
            for mount in device.get("mountpoints") or []:
                if mount:
                    mounts.add(mount)
    return tuple(sorted(mounts))


def _top_level_device(source: str) -> str | None:
    if not source.startswith("/dev/"):
        return None
    completed = _command(["lsblk", "-s", "-n", "-o", "PATH,TYPE", source])
    if completed.returncode != 0:
        return None
    candidates = []
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == "disk":
            candidates.append(str(Path(fields[0]).resolve()))
    return candidates[-1] if candidates else str(Path(source).resolve())


def protected_top_level_devices() -> dict[str, str]:
    protected: dict[str, str] = {}
    targets = [
        ("host root", Path("/")),
        ("installer source filesystem", PROJECT_ROOT),
        ("Arch installation media", Path("/run/archiso/bootmnt")),
        ("live installation media", Path("/run/live/medium")),
        ("mounted installation media", Path("/cdrom")),
    ]
    for label, target in targets:
        if label not in {"host root", "installer source filesystem"} and not target.exists():
            continue
        completed = _command(["findmnt", "-n", "-o", "SOURCE", "-T", str(target)])
        if completed.returncode != 0:
            continue
        device = _top_level_device(completed.stdout.strip())
        if device:
            protected[label] = device
    return protected


def _protection_reasons(path: Path) -> tuple[str, ...]:
    reasons = set()
    for label, protected in protected_top_level_devices().items():
        if str(path) != protected:
            continue
        reasons.add(
            StorageRejection.RUNNING_SYSTEM
            if label == "host root"
            else StorageRejection.INSTALLATION_MEDIA
        )
    return tuple(sorted(str(reason) for reason in reasons))


def _stable_ids(path: Path) -> tuple[str, ...]:
    values: set[str] = set()
    try:
        entries = tuple(DEV_DISK_BY_ID.iterdir())
    except OSError:
        return ()
    resolved = str(path.resolve())
    for entry in entries:
        try:
            if str(entry.resolve(strict=True)) == resolved:
                values.add(entry.name)
        except OSError:
            continue
    return tuple(sorted(values))


def _read_only(value: Any) -> bool | None:
    if value in (0, "0", False):
        return False
    if value in (1, "1", True):
        return True
    return None


def _with_eligibility(
    state: DiskState,
    minimum_capacity_bytes: int,
    duplicate_tokens: frozenset[str] = frozenset(),
) -> DiskState:
    eligibility = evaluate_storage_eligibility(
        target_type=state.target_type,
        device_type="disk" if state.target_type in {"block", "image"} else state.target_type,
        size_bytes=state.size_bytes,
        minimum_capacity_bytes=max(ABSOLUTE_MINIMUM_BYTES, minimum_capacity_bytes),
        identity=state.identity,
        mounted_paths=state.mounted_paths,
        read_only=state.read_only,
        protection_reasons=state.protection_reasons,
        observation_errors=state.observation_errors,
        duplicate_tokens=duplicate_tokens,
    )
    return replace(state, eligibility=eligibility)


def _discover_image(path: Path) -> DiskState:
    resolved = path.resolve(strict=True)
    details = resolved.stat()
    if not stat.S_ISREG(details.st_mode):
        raise kitpro_repo.PipelineError(f"image target is not a regular file: {resolved}")
    marker = marker_path(resolved)
    if not marker.is_file():
        raise kitpro_repo.PipelineError(
            f"image target lacks a KITPro disposable-disk marker: {marker}"
        )
    marker_document = kitpro_repo.load_json(marker)
    if marker_document != {
        "schema_version": 1,
        "purpose": "KITPro Linux Phase 3 disposable test disk",
        "path": str(resolved),
        "size_bytes": details.st_size,
    }:
        raise kitpro_repo.PipelineError("test-disk marker does not match the target identity")
    return DiskState(
        path=str(resolved),
        target_type="image",
        size_bytes=details.st_size,
        identity={"st_dev": details.st_dev, "st_ino": details.st_ino},
        mounted_paths=_loop_mounts(resolved),
        signatures=_signatures(resolved),
        partition_table=_partition_table(resolved),
        marker_sha256=kitpro_repo.sha256_file(marker),
        read_only=False,
    )


def _flatten_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for device in devices:
        flattened.append(device)
        flattened.extend(_flatten_devices(device.get("children", [])))
    return flattened


def _enumerated_disks() -> list[dict[str, Any]]:
    completed = _command(
        ["lsblk", "-J", "-b", "-d", "-o", "PATH,TYPE,SIZE,MODEL,SERIAL,WWN,RO,TRAN"]
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"cannot enumerate installation disks: {completed.stderr.strip()}"
        )
    try:
        devices = json.loads(completed.stdout).get("blockdevices", [])
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("lsblk returned invalid disk inventory JSON") from error
    if not isinstance(devices, list):
        raise kitpro_repo.PipelineError("lsblk returned an invalid disk inventory")
    return [
        item for item in devices if item.get("type") == "disk" and isinstance(item.get("path"), str)
    ]


def _inventory_identities(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    identities = []
    for item in rows:
        path = Path(item["path"])
        identities.append(
            {
                "model": item.get("model"),
                "serial": item.get("serial"),
                "wwn": item.get("wwn"),
                "stable_ids": list(_stable_ids(path)),
            }
        )
    return identities


def discover_storage_inventory(
    minimum_capacity_bytes: int = ABSOLUTE_MINIMUM_BYTES,
) -> list[DiskState]:
    """Return all inspectable whole disks, including explicitly rejected disks."""
    rows = _enumerated_disks()
    duplicate_tokens = duplicate_identity_tokens(_inventory_identities(rows))
    observed: list[DiskState] = []
    for item in rows:
        try:
            state = _discover_block(Path(item["path"]))
        except (kitpro_repo.PipelineError, OSError):
            # A path that cannot be inspected is not eligible.  It cannot be
            # represented safely without trustworthy capacity and identity.
            continue
        observed.append(_with_eligibility(state, minimum_capacity_bytes, duplicate_tokens))
    return sorted(observed, key=lambda disk: disk.path)


def list_installable_disks(
    minimum_capacity_bytes: int = ABSOLUTE_MINIMUM_BYTES,
) -> list[DiskState]:
    """Return only whole block disks accepted by the authoritative policy."""
    return [
        disk
        for disk in discover_storage_inventory(minimum_capacity_bytes)
        if disk.eligibility.eligible
    ]


def _discover_block(path: Path) -> DiskState:
    resolved = path.resolve(strict=True)
    if not stat.S_ISBLK(resolved.stat().st_mode):
        raise kitpro_repo.PipelineError(f"block target is not a block device: {resolved}")
    completed = _command(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            (
                "PATH,TYPE,SIZE,START,LOG-SEC,PARTTYPE,PARTUUID,FSTYPE,UUID,LABEL,"
                "PARTLABEL,MOUNTPOINTS,PKNAME,MODEL,SERIAL,WWN"
                ",RO,TRAN"
            ),
            str(resolved),
        ]
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"cannot inspect block target {resolved}: {completed.stderr.strip()}"
        )
    devices = _flatten_devices(json.loads(completed.stdout).get("blockdevices", []))
    target = next(
        (item for item in devices if str(Path(item["path"]).resolve()) == str(resolved)), None
    )
    if target is None or target.get("type") != "disk":
        raise kitpro_repo.PipelineError(
            "target must be a complete block disk, not a partition or mapper"
        )
    mounts = sorted(
        {mount for item in devices for mount in (item.get("mountpoints") or []) if mount}
    )
    partitions = []
    for item in devices:
        if item.get("type") != "part":
            continue
        raw_path = str(item.get("path", ""))
        match = __import__("re").search(r"(?:p)?(\d+)$", raw_path)
        partitions.append(
            {
                "path": raw_path,
                "number": int(match.group(1)) if match else 0,
                "start_bytes": int(item.get("start") or 0) * int(item.get("log-sec") or 512),
                "size_bytes": int(item.get("size") or 0),
                "partition_type": item.get("parttype") or None,
                "partition_uuid": item.get("partuuid") or None,
                "filesystem": item.get("fstype") or None,
                "filesystem_uuid": item.get("uuid") or None,
                "filesystem_label": item.get("label") or None,
                "partition_label": item.get("partlabel") or None,
                "mount_points": tuple(value for value in item.get("mountpoints") or [] if value),
            }
        )
    stable_ids = _stable_ids(resolved)
    return DiskState(
        path=str(resolved),
        target_type="block",
        size_bytes=int(target["size"]),
        identity={
            "model": target.get("model"),
            "serial": target.get("serial"),
            "wwn": target.get("wwn"),
            "stable_ids": list(stable_ids),
        },
        mounted_paths=tuple(mounts),
        signatures=_signatures(resolved),
        partition_table=_partition_table(resolved),
        marker_sha256=None,
        partitions=tuple(
            sorted(partitions, key=lambda item: (item["start_bytes"], item["number"]))
        ),
        transport=(str(target.get("tran")).lower() if target.get("tran") else None),
        read_only=_read_only(target.get("ro")),
        stable_ids=stable_ids,
        protection_reasons=_protection_reasons(resolved),
    )


def discover_disk(path: Path, target_type: str, minimum_capacity_bytes: int) -> DiskState:
    if not path.exists():
        raise kitpro_repo.PipelineError(f"target disk does not exist: {path}")
    if target_type not in {"block", "image"}:
        raise kitpro_repo.PipelineError(f"unsupported target disk type: {target_type}")
    if target_type == "block":
        resolved = str(path.resolve(strict=True))
        for label, protected in protected_top_level_devices().items():
            if resolved == protected:
                raise kitpro_repo.PipelineError(f"refusing to select the {label} disk: {resolved}")
    state = _discover_image(path) if target_type == "image" else _discover_block(path)
    duplicate_tokens = frozenset()
    if target_type == "block":
        rows = _enumerated_disks()
        duplicate_tokens = duplicate_identity_tokens(_inventory_identities(rows))
    state = _with_eligibility(state, minimum_capacity_bytes, duplicate_tokens)
    if not state.eligibility.eligible:
        reasons = "; ".join(rejection_message(item) for item in state.eligibility.rejection_reasons)
        raise kitpro_repo.PipelineError(f"target disk is ineligible: {reasons}")
    return state


def require_erase_authorization(allowed: bool) -> None:
    if not allowed:
        raise kitpro_repo.PipelineError("destructive installation requires --allow-disk-erase")


def assert_disk_unchanged(planned: dict[str, Any], current: DiskState) -> None:
    if planned.get("path") != current.path:
        raise kitpro_repo.PipelineError("target disk path changed after planning")
    if planned.get("identity") != current.identity:
        raise kitpro_repo.PipelineError("target disk identity changed after planning")
    if planned.get("size_bytes") != current.size_bytes:
        raise kitpro_repo.PipelineError("target disk capacity changed after planning")
    if planned != current.to_dict():
        raise kitpro_repo.PipelineError(
            "target disk state changed after planning or the observation is stale; "
            "generate a new install plan"
        )
