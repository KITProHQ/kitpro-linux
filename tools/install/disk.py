"""Read-only disk discovery and fail-closed target checks."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools import kitpro_repo
from tools.install.model import ABSOLUTE_MINIMUM_BYTES


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DISK_ROOT = PROJECT_ROOT / ".state/phase3/test-disks"


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

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["mounted_paths"] = list(self.mounted_paths)
        value["signatures"] = list(self.signatures)
        return value


def marker_path(target: Path) -> Path:
    return target.with_name(target.name + ".kitpro-test-disk.json")


def create_test_disk(target: Path, size_bytes: int) -> dict[str, Any]:
    if not target.is_absolute():
        raise kitpro_repo.PipelineError("test disk path must be absolute")
    if size_bytes < ABSOLUTE_MINIMUM_BYTES:
        raise kitpro_repo.PipelineError("test disk is smaller than the installer absolute minimum")
    if target.exists() or marker_path(target).exists():
        raise kitpro_repo.PipelineError(f"refusing to replace existing test disk or marker: {target}")
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
    return subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )


def _signatures(path: Path) -> tuple[dict[str, Any], ...]:
    completed = _command(
        ["wipefs", "--json", "--output", "DEVICE,OFFSET,TYPE,UUID,LABEL", str(path)]
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(f"cannot inspect signatures on {path}: {completed.stderr.strip()}")
    document = json.loads(completed.stdout or "{}")
    signatures = document.get("signatures", [])
    if not isinstance(signatures, list):
        raise kitpro_repo.PipelineError(f"wipefs returned an invalid signature inventory for {path}")
    return tuple(sorted(signatures, key=lambda item: (str(item.get("offset")), str(item.get("type")))))


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
    for label, target in (("host root", Path("/")), ("installer source filesystem", PROJECT_ROOT)):
        completed = _command(["findmnt", "-n", "-o", "SOURCE", "-T", str(target)])
        if completed.returncode != 0:
            continue
        device = _top_level_device(completed.stdout.strip())
        if device:
            protected[label] = device
    return protected


def _discover_image(path: Path) -> DiskState:
    resolved = path.resolve(strict=True)
    details = resolved.stat()
    if not stat.S_ISREG(details.st_mode):
        raise kitpro_repo.PipelineError(f"image target is not a regular file: {resolved}")
    marker = marker_path(resolved)
    if not marker.is_file():
        raise kitpro_repo.PipelineError(f"image target lacks a KITPro disposable-disk marker: {marker}")
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
    )


def _flatten_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flattened: list[dict[str, Any]] = []
    for device in devices:
        flattened.append(device)
        flattened.extend(_flatten_devices(device.get("children", [])))
    return flattened


def list_installable_disks(
    minimum_capacity_bytes: int = ABSOLUTE_MINIMUM_BYTES,
) -> list[DiskState]:
    """Return only whole block disks accepted by the authoritative safety checks."""
    completed = _command(
        ["lsblk", "-J", "-b", "-d", "-o", "PATH,TYPE,SIZE,MODEL,SERIAL,WWN"]
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
    accepted: list[DiskState] = []
    for item in devices:
        if item.get("type") != "disk" or not isinstance(item.get("path"), str):
            continue
        try:
            accepted.append(
                discover_disk(Path(item["path"]), "block", minimum_capacity_bytes)
            )
        except (kitpro_repo.PipelineError, OSError):
            # Rejected targets stay unavailable to the guided interface. The
            # underlying discovery routine remains the sole policy owner.
            continue
    return sorted(accepted, key=lambda disk: disk.path)


def _discover_block(path: Path) -> DiskState:
    resolved = path.resolve(strict=True)
    if not stat.S_ISBLK(resolved.stat().st_mode):
        raise kitpro_repo.PipelineError(f"block target is not a block device: {resolved}")
    completed = _command(
        [
            "lsblk", "-J", "-b", "-o",
            "PATH,TYPE,SIZE,MOUNTPOINTS,PKNAME,MODEL,SERIAL,WWN", str(resolved),
        ]
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(f"cannot inspect block target {resolved}: {completed.stderr.strip()}")
    devices = _flatten_devices(json.loads(completed.stdout).get("blockdevices", []))
    target = next((item for item in devices if str(Path(item["path"]).resolve()) == str(resolved)), None)
    if target is None or target.get("type") != "disk":
        raise kitpro_repo.PipelineError("target must be a complete block disk, not a partition or mapper")
    for label, protected in protected_top_level_devices().items():
        if str(resolved) == protected:
            raise kitpro_repo.PipelineError(f"refusing to select the {label} disk: {resolved}")
    mounts = sorted(
        {
            mount
            for item in devices
            for mount in (item.get("mountpoints") or [])
            if mount
        }
    )
    return DiskState(
        path=str(resolved),
        target_type="block",
        size_bytes=int(target["size"]),
        identity={
            "model": target.get("model"),
            "serial": target.get("serial"),
            "wwn": target.get("wwn"),
        },
        mounted_paths=tuple(mounts),
        signatures=_signatures(resolved),
        partition_table=_partition_table(resolved),
        marker_sha256=None,
    )


def discover_disk(path: Path, target_type: str, minimum_capacity_bytes: int) -> DiskState:
    if not path.exists():
        raise kitpro_repo.PipelineError(f"target disk does not exist: {path}")
    state = _discover_image(path) if target_type == "image" else _discover_block(path)
    required = max(ABSOLUTE_MINIMUM_BYTES, minimum_capacity_bytes)
    if state.size_bytes < required:
        raise kitpro_repo.PipelineError(
            f"target disk is too small: {state.size_bytes} bytes; {required} bytes required"
        )
    if state.mounted_paths:
        raise kitpro_repo.PipelineError(
            f"target disk or a child partition is mounted: {list(state.mounted_paths)}"
        )
    return state


def require_erase_authorization(allowed: bool) -> None:
    if not allowed:
        raise kitpro_repo.PipelineError("destructive installation requires --allow-disk-erase")


def assert_disk_unchanged(planned: dict[str, Any], current: DiskState) -> None:
    if planned != current.to_dict():
        raise kitpro_repo.PipelineError(
            "target disk state changed after planning; generate a new install plan"
        )
