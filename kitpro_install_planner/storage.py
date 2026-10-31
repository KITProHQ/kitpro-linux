"""Original, deterministic KITPro whole-disk storage planning.

The planner models only the layouts that the KITPro execution engine can fully
install and verify on one fresh GPT disk. It deliberately performs no device
discovery or I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

MIB = 1024**2
GIB = 1024**3
STORAGE_SCHEMA_VERSION = 1
STORAGE_SCHEMA_V2 = 2
STORAGE_SCHEMA_V3 = 3
STORAGE_SCHEMA_V4 = 4
STORAGE_SCHEMA_V5 = 5
STORAGE_SCHEMA_V6 = 6
STORAGE_SCHEMA_V7 = 7
# systemd-repart enforces the UEFI-safe 260 MiB physical ESP allocation even
# when the product policy requests 256 MiB. Model the bytes the engine creates
# so the authoritative plan and post-install boundary checks agree.
ESP_BYTES = 260 * MIB
DEFAULT_ALIGNMENT_BYTES = MIB
GPT_ENTRY_COUNT = 128
GPT_ENTRY_BYTES = 128
MINIMUM_ROOT_BYTES = 5 * GIB
MINIMUM_HOME_BYTES = GIB
MINIMUM_SWAP_BYTES = 256 * MIB
SUPPORTED_LAYOUTS = {"standard", "separate-home", "root-swap", "root-home-swap"}
SUPPORTED_BTRFS_SUBVOLUMES = {
    "@": "/",
    "@home": "/home",
    "@snapshots": "/.snapshots",
}
SUPPORTED_BTRFS_COMPRESSION = {"none", "zstd"}
SUPPORTED_ENCRYPTED_FILESYSTEMS = {"ext4", "btrfs"}
SUPPORTED_MANUAL_ROLES = {"esp", "root", "home", "var", "srv", "swap"}
MANUAL_ROLE_POLICY = {
    "esp": ({"vfat"}, "/efi", "esp", ESP_BYTES),
    "root": ({"ext4", "btrfs"}, "/", "root-x86-64", MINIMUM_ROOT_BYTES),
    "home": ({"ext4"}, "/home", "home", MINIMUM_HOME_BYTES),
    "var": ({"ext4"}, "/var", "linux-generic", GIB),
    "srv": ({"ext4"}, "/srv", "linux-generic", GIB),
    "swap": ({"swap"}, None, "swap", MINIMUM_SWAP_BYTES),
}
LUKS_MAPPER_NAME = "cryptroot"
LUKS_LVM_MAPPER_NAME = "cryptlvm"
LUKS2_METADATA_BYTES = 16 * MIB
LUKS_PBKDF = "argon2id"
LUKS_ITER_TIME_MS = 2000
LUKS_PBKDF_MEMORY_KIB = 262144
LUKS_PBKDF_PARALLEL_THREADS = 2
DEFAULT_LVM_EXTENT_BYTES = 4 * MIB
LVM_METADATA_EXTENTS = 1
SUPPORTED_LVM_ROLES = {"root", "home", "var", "srv", "swap"}
LVM_ROLE_POLICY = {
    "root": ({"ext4"}, "/", MINIMUM_ROOT_BYTES),
    "home": ({"ext4"}, "/home", MINIMUM_HOME_BYTES),
    "var": ({"ext4"}, "/var", GIB),
    "srv": ({"ext4"}, "/srv", GIB),
    "swap": ({"swap"}, None, MINIMUM_SWAP_BYTES),
}


class StoragePlanningError(ValueError):
    """The requested custom layout is unsafe, inconsistent, or unsupported."""


@dataclass(frozen=True, slots=True)
class StorageRequestV1:
    layout: str = "standard"
    root_size_bytes: int | None = None
    swap_size_bytes: int | None = None
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    schema_version: int = STORAGE_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value: dict[str, Any] | None) -> StorageRequestV1:
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "layout",
            "root_size_bytes",
            "swap_size_bytes",
            "logical_sector_bytes",
            "physical_sector_bytes",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        try:
            return cls(**value)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "layout": self.layout,
            "root_size_bytes": self.root_size_bytes,
            "swap_size_bytes": self.swap_size_bytes,
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV2:
    """Versioned Btrfs storage request; v1 remains the ext4 contract."""

    layout: str = "standard"
    root_size_bytes: int | None = None
    swap_size_bytes: int | None = None
    subvolumes: tuple[str, ...] = ("@",)
    compression: str = "zstd"
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    filesystem: str = "btrfs"
    schema_version: int = STORAGE_SCHEMA_V2

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV2:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "layout",
            "root_size_bytes",
            "swap_size_bytes",
            "subvolumes",
            "compression",
            "logical_sector_bytes",
            "physical_sector_bytes",
            "filesystem",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        normalized = dict(value)
        subvolumes = normalized.get("subvolumes", ("@",))
        if not isinstance(subvolumes, (list, tuple)) or not all(
            isinstance(item, str) for item in subvolumes
        ):
            raise StoragePlanningError("disk.storage.subvolumes must be an array of names")
        normalized["subvolumes"] = tuple(subvolumes)
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "layout": self.layout,
            "root_size_bytes": self.root_size_bytes,
            "swap_size_bytes": self.swap_size_bytes,
            "subvolumes": list(self.subvolumes),
            "compression": self.compression,
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
            "filesystem": self.filesystem,
        }


@dataclass(frozen=True, slots=True)
class EncryptionRequestV1:
    """Non-secret LUKS policy. The passphrase is a runtime secret, never plan data."""

    enabled: bool = True
    luks_version: int = 2
    mapper_name: str = LUKS_MAPPER_NAME
    pbkdf: str = LUKS_PBKDF
    keyslot: int = 0
    iter_time_ms: int = LUKS_ITER_TIME_MS
    pbkdf_memory_kib: int = LUKS_PBKDF_MEMORY_KIB
    pbkdf_parallel_threads: int = LUKS_PBKDF_PARALLEL_THREADS
    schema_version: int = 1

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> EncryptionRequestV1:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage.encryption must be an object")
        allowed = {
            "enabled",
            "luks_version",
            "mapper_name",
            "pbkdf",
            "keyslot",
            "iter_time_ms",
            "pbkdf_memory_kib",
            "pbkdf_parallel_threads",
            "schema_version",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(
                f"disk.storage.encryption contains unsupported fields: {unknown}"
            )
        try:
            return cls(**value)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage.encryption: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "luks_version": self.luks_version,
            "mapper_name": self.mapper_name,
            "pbkdf": self.pbkdf,
            "keyslot": self.keyslot,
            "iter_time_ms": self.iter_time_ms,
            "pbkdf_memory_kib": self.pbkdf_memory_kib,
            "pbkdf_parallel_threads": self.pbkdf_parallel_threads,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV3:
    """Encrypted root storage request; secrets are supplied only at execution."""

    layout: str = "standard"
    subvolumes: tuple[str, ...] = ()
    compression: str = "none"
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    filesystem: str = "ext4"
    encryption: EncryptionRequestV1 = EncryptionRequestV1()
    schema_version: int = STORAGE_SCHEMA_V3

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV3:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "layout",
            "subvolumes",
            "compression",
            "logical_sector_bytes",
            "physical_sector_bytes",
            "filesystem",
            "encryption",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        normalized = dict(value)
        subvolumes = normalized.get("subvolumes", ())
        if not isinstance(subvolumes, (list, tuple)) or not all(
            isinstance(item, str) for item in subvolumes
        ):
            raise StoragePlanningError("disk.storage.subvolumes must be an array of names")
        normalized["subvolumes"] = tuple(subvolumes)
        normalized["encryption"] = EncryptionRequestV1.from_dict(normalized.get("encryption", {}))
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "layout": self.layout,
            "subvolumes": list(self.subvolumes),
            "compression": self.compression,
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
            "filesystem": self.filesystem,
            "encryption": self.encryption.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ManualPartitionV1:
    """One requested GPT partition in a whole-disk replacement layout."""

    role: str
    filesystem: str
    mount_point: str | None
    size_bytes: int | None = None
    use_remaining: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ManualPartitionV1:
        if not isinstance(value, dict):
            raise StoragePlanningError("manual partition must be an object")
        allowed = {"role", "filesystem", "mount_point", "size_bytes", "use_remaining"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"manual partition contains unsupported fields: {unknown}")
        try:
            return cls(**value)
        except TypeError as error:
            raise StoragePlanningError(f"invalid manual partition: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "filesystem": self.filesystem,
            "mount_point": self.mount_point,
            "size_bytes": self.size_bytes,
            "use_remaining": self.use_remaining,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV4:
    """Explicit, ordered manual GPT layout for one replaceable whole disk."""

    partitions: tuple[ManualPartitionV1, ...] = ()
    subvolumes: tuple[str, ...] = ()
    compression: str = "none"
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    encryption: EncryptionRequestV1 | None = None
    schema_version: int = STORAGE_SCHEMA_V4

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV4:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "partitions",
            "subvolumes",
            "compression",
            "logical_sector_bytes",
            "physical_sector_bytes",
            "encryption",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        raw_partitions = value.get("partitions", ())
        if not isinstance(raw_partitions, (list, tuple)):
            raise StoragePlanningError("disk.storage.partitions must be an array")
        raw_subvolumes = value.get("subvolumes", ())
        if not isinstance(raw_subvolumes, (list, tuple)) or not all(
            isinstance(item, str) for item in raw_subvolumes
        ):
            raise StoragePlanningError("disk.storage.subvolumes must be an array of names")
        normalized = dict(value)
        normalized["partitions"] = tuple(
            ManualPartitionV1.from_dict(item) for item in raw_partitions
        )
        normalized["subvolumes"] = tuple(raw_subvolumes)
        if normalized.get("encryption") is not None:
            normalized["encryption"] = EncryptionRequestV1.from_dict(normalized["encryption"])
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "partitions": [item.to_dict() for item in self.partitions],
            "subvolumes": list(self.subvolumes),
            "compression": self.compression,
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
            "encryption": self.encryption.to_dict() if self.encryption else None,
        }


@dataclass(frozen=True, slots=True)
class LogicalVolumeV1:
    """One standard linear logical volume inside the installer-owned VG."""

    name: str
    role: str
    filesystem: str
    mount_point: str | None
    size_bytes: int | None = None
    use_remaining: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> LogicalVolumeV1:
        if not isinstance(value, dict):
            raise StoragePlanningError("logical volume must be an object")
        allowed = {"name", "role", "filesystem", "mount_point", "size_bytes", "use_remaining"}
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"logical volume contains unsupported fields: {unknown}")
        try:
            return cls(**value)
        except TypeError as error:
            raise StoragePlanningError(f"invalid logical volume: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "filesystem": self.filesystem,
            "mount_point": self.mount_point,
            "size_bytes": self.size_bytes,
            "use_remaining": self.use_remaining,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV5:
    """One-disk LVM2 layout with one PV, one VG, and linear ext4/swap LVs."""

    volume_group: str = "vgkitpro"
    extent_size_bytes: int = DEFAULT_LVM_EXTENT_BYTES
    logical_volumes: tuple[LogicalVolumeV1, ...] = ()
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    schema_version: int = STORAGE_SCHEMA_V5

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV5:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "volume_group",
            "extent_size_bytes",
            "logical_volumes",
            "logical_sector_bytes",
            "physical_sector_bytes",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        raw_volumes = value.get("logical_volumes", ())
        if not isinstance(raw_volumes, (list, tuple)):
            raise StoragePlanningError("disk.storage.logical_volumes must be an array")
        normalized = dict(value)
        normalized["logical_volumes"] = tuple(
            LogicalVolumeV1.from_dict(item) for item in raw_volumes
        )
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "volume_group": self.volume_group,
            "extent_size_bytes": self.extent_size_bytes,
            "logical_volumes": [item.to_dict() for item in self.logical_volumes],
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV6:
    """One-disk LVM2 layout inside one protected LUKS2 container."""

    volume_group: str = "vgkitpro"
    extent_size_bytes: int = DEFAULT_LVM_EXTENT_BYTES
    logical_volumes: tuple[LogicalVolumeV1, ...] = ()
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    encryption: EncryptionRequestV1 = EncryptionRequestV1(mapper_name=LUKS_LVM_MAPPER_NAME)
    schema_version: int = STORAGE_SCHEMA_V6

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV6:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "volume_group",
            "extent_size_bytes",
            "logical_volumes",
            "logical_sector_bytes",
            "physical_sector_bytes",
            "encryption",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        raw_volumes = value.get("logical_volumes", ())
        if not isinstance(raw_volumes, (list, tuple)):
            raise StoragePlanningError("disk.storage.logical_volumes must be an array")
        normalized = dict(value)
        normalized["logical_volumes"] = tuple(
            LogicalVolumeV1.from_dict(item) for item in raw_volumes
        )
        normalized["encryption"] = EncryptionRequestV1.from_dict(
            normalized.get("encryption", {"mapper_name": LUKS_LVM_MAPPER_NAME})
        )
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "volume_group": self.volume_group,
            "extent_size_bytes": self.extent_size_bytes,
            "logical_volumes": [item.to_dict() for item in self.logical_volumes],
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
            "encryption": self.encryption.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ExistingPartitionV1:
    """One observed GPT partition and its explicit preservation action."""

    number: int
    start_bytes: int
    size_bytes: int
    partition_type: str
    partition_uuid: str
    filesystem: str | None = None
    filesystem_uuid: str | None = None
    label: str | None = None
    action: str = "preserve"
    role: str | None = None
    format_as: str | None = None

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ExistingPartitionV1:
        if not isinstance(value, dict):
            raise StoragePlanningError("existing partition must be an object")
        allowed = {
            "number",
            "start_bytes",
            "size_bytes",
            "partition_type",
            "partition_uuid",
            "filesystem",
            "filesystem_uuid",
            "label",
            "action",
            "role",
            "format_as",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"existing partition contains unsupported fields: {unknown}")
        try:
            return cls(**value)
        except TypeError as error:
            raise StoragePlanningError(f"invalid existing partition: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "start_bytes": self.start_bytes,
            "size_bytes": self.size_bytes,
            "partition_type": self.partition_type,
            "partition_uuid": self.partition_uuid,
            "filesystem": self.filesystem,
            "filesystem_uuid": self.filesystem_uuid,
            "label": self.label,
            "action": self.action,
            "role": self.role,
            "format_as": self.format_as,
        }


@dataclass(frozen=True, slots=True)
class NewPartitionV1:
    """One new partition allocated only inside verified GPT free space."""

    role: str
    filesystem: str
    mount_point: str | None
    size_bytes: int | None = None
    use_remaining: bool = False

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> NewPartitionV1:
        manual = ManualPartitionV1.from_dict(value)
        return cls(**manual.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "filesystem": self.filesystem,
            "mount_point": self.mount_point,
            "size_bytes": self.size_bytes,
            "use_remaining": self.use_remaining,
        }


@dataclass(frozen=True, slots=True)
class StorageRequestV7:
    """Incremental GPT layout that preserves explicitly bound partitions."""

    existing_partitions: tuple[ExistingPartitionV1, ...] = ()
    new_partitions: tuple[NewPartitionV1, ...] = ()
    subvolumes: tuple[str, ...] = ()
    compression: str = "none"
    logical_sector_bytes: int = 512
    physical_sector_bytes: int = 4096
    schema_version: int = STORAGE_SCHEMA_V7

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> StorageRequestV7:
        if not isinstance(value, dict):
            raise StoragePlanningError("disk.storage must be an object")
        allowed = {
            "schema_version",
            "existing_partitions",
            "new_partitions",
            "subvolumes",
            "compression",
            "logical_sector_bytes",
            "physical_sector_bytes",
        }
        unknown = sorted(set(value) - allowed)
        if unknown:
            raise StoragePlanningError(f"disk.storage contains unsupported fields: {unknown}")
        existing = value.get("existing_partitions", ())
        new = value.get("new_partitions", ())
        subvolumes = value.get("subvolumes", ())
        if not isinstance(existing, (list, tuple)) or not isinstance(new, (list, tuple)):
            raise StoragePlanningError("preservation partition lists must be arrays")
        if not isinstance(subvolumes, (list, tuple)) or not all(
            isinstance(item, str) for item in subvolumes
        ):
            raise StoragePlanningError("disk.storage.subvolumes must be an array of names")
        normalized = dict(value)
        normalized["existing_partitions"] = tuple(
            ExistingPartitionV1.from_dict(item) for item in existing
        )
        normalized["new_partitions"] = tuple(NewPartitionV1.from_dict(item) for item in new)
        normalized["subvolumes"] = tuple(subvolumes)
        try:
            return cls(**normalized)
        except TypeError as error:
            raise StoragePlanningError(f"invalid disk.storage: {error}") from error

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "existing_partitions": [item.to_dict() for item in self.existing_partitions],
            "new_partitions": [item.to_dict() for item in self.new_partitions],
            "subvolumes": list(self.subvolumes),
            "compression": self.compression,
            "logical_sector_bytes": self.logical_sector_bytes,
            "physical_sector_bytes": self.physical_sector_bytes,
        }


StorageRequest = (
    StorageRequestV1
    | StorageRequestV2
    | StorageRequestV3
    | StorageRequestV4
    | StorageRequestV5
    | StorageRequestV6
    | StorageRequestV7
)


def storage_request_from_dict(value: dict[str, Any] | None) -> StorageRequest:
    if value is not None and not isinstance(value, dict):
        raise StoragePlanningError("disk.storage must be an object")
    if (
        value is None
        or value.get("schema_version", STORAGE_SCHEMA_VERSION) == STORAGE_SCHEMA_VERSION
    ):
        return StorageRequestV1.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V2:
        return StorageRequestV2.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V3:
        return StorageRequestV3.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V4:
        return StorageRequestV4.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V5:
        return StorageRequestV5.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V6:
        return StorageRequestV6.from_dict(value)
    if value.get("schema_version") == STORAGE_SCHEMA_V7:
        return StorageRequestV7.from_dict(value)
    raise StoragePlanningError(f"unsupported storage schema version: {value.get('schema_version')}")


def _positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise StoragePlanningError(f"{field} must be a positive integer")
    return value


def _align_up(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


def _align_down(value: int, alignment: int) -> int:
    return (value // alignment) * alignment


def _partition(
    role: str,
    start: int,
    size: int,
    filesystem: str,
    mount_point: str | None,
    partition_type: str,
    size_policy: str,
) -> dict[str, Any]:
    return {
        "role": role,
        "start_bytes": start,
        "size_bytes": size,
        "end_bytes": start + size,
        "size_policy": size_policy,
        "partition_type": partition_type,
        "filesystem": filesystem,
        "mount_point": mount_point,
    }


def plan_storage_v1(disk_size_bytes: int, request: StorageRequestV1) -> dict[str, Any]:
    """Return an ordered, non-overlapping whole-disk GPT layout."""
    disk_size = _positive_integer(disk_size_bytes, "target size_bytes")
    logical = _positive_integer(request.logical_sector_bytes, "logical sector size")
    physical = _positive_integer(request.physical_sector_bytes, "physical sector size")
    if request.schema_version != STORAGE_SCHEMA_VERSION:
        raise StoragePlanningError(f"unsupported storage schema version: {request.schema_version}")
    if request.layout not in SUPPORTED_LAYOUTS:
        raise StoragePlanningError(f"unsupported storage layout: {request.layout}")
    if logical & (logical - 1) or physical & (physical - 1):
        raise StoragePlanningError("sector sizes must be powers of two")
    if logical < 512 or physical < logical or physical % logical:
        raise StoragePlanningError("physical and logical sector sizes are inconsistent")

    alignment = max(DEFAULT_ALIGNMENT_BYTES, physical)
    if alignment % logical:
        alignment = _align_up(alignment, logical)
    entry_array_bytes = _align_up(GPT_ENTRY_COUNT * GPT_ENTRY_BYTES, logical)
    first_usable = _align_up(2 * logical + entry_array_bytes, alignment)
    last_usable_exclusive = _align_down(
        disk_size - logical - entry_array_bytes,
        alignment,
    )
    if last_usable_exclusive <= first_usable:
        raise StoragePlanningError("target has no usable GPT-aligned space")

    cursor = first_usable
    partitions = [_partition("esp", cursor, ESP_BYTES, "vfat", "/efi", "esp", "fixed")]
    cursor += ESP_BYTES
    available = last_usable_exclusive - cursor

    wants_home = request.layout in {"separate-home", "root-home-swap"}
    wants_swap = request.layout in {"root-swap", "root-home-swap"}
    swap_size = 0
    if wants_swap:
        swap_size = request.swap_size_bytes or 2 * GIB
        _positive_integer(swap_size, "swap size")
        swap_size = _align_up(swap_size, alignment)
        if swap_size < MINIMUM_SWAP_BYTES:
            raise StoragePlanningError("swap must be at least 256 MiB")
    elif request.swap_size_bytes is not None:
        raise StoragePlanningError("swap size requires a layout with swap")

    if wants_home:
        root_size = request.root_size_bytes or max(MINIMUM_ROOT_BYTES, available // 2)
        _positive_integer(root_size, "root size")
        root_size = _align_up(root_size, alignment)
        if root_size < MINIMUM_ROOT_BYTES:
            raise StoragePlanningError("root must be at least 5 GiB")
        home_size = available - root_size - swap_size
        home_size = _align_down(home_size, alignment)
        if home_size < MINIMUM_HOME_BYTES:
            raise StoragePlanningError("custom layout leaves less than 1 GiB for /home")
    else:
        if request.root_size_bytes is not None:
            raise StoragePlanningError("fixed root size requires a separate /home layout")
        root_size = _align_down(available - swap_size, alignment)
        home_size = 0
        if root_size < MINIMUM_ROOT_BYTES:
            raise StoragePlanningError("custom layout leaves less than 5 GiB for root")

    partitions.append(
        _partition(
            "root",
            cursor,
            root_size,
            "ext4",
            "/",
            "root-x86-64",
            "fixed" if wants_home or wants_swap else "remaining",
        )
    )
    cursor += root_size
    if wants_home:
        partitions.append(
            _partition("home", cursor, home_size, "ext4", "/home", "home", "remaining")
        )
        cursor += home_size
    if wants_swap:
        partitions.append(_partition("swap", cursor, swap_size, "swap", None, "swap", "fixed"))
        cursor += swap_size

    if cursor > last_usable_exclusive:
        raise StoragePlanningError("partition layout exceeds usable target capacity")
    previous_end = first_usable
    mount_points: set[str] = set()
    for partition in partitions:
        if partition["start_bytes"] < previous_end:
            raise StoragePlanningError("partition layout overlaps")
        if partition["start_bytes"] % alignment or partition["size_bytes"] % alignment:
            raise StoragePlanningError("partition layout is not correctly aligned")
        mount = partition["mount_point"]
        if mount is not None and mount in mount_points:
            raise StoragePlanningError(f"duplicate mount point: {mount}")
        if mount is not None:
            mount_points.add(mount)
        previous_end = partition["end_bytes"]
    if mount_points < {"/", "/efi"}:
        raise StoragePlanningError("layout requires root and EFI mount points")

    return {
        "schema_version": STORAGE_SCHEMA_VERSION,
        "layout": request.layout,
        "disk_size_bytes": disk_size,
        "logical_sector_bytes": logical,
        "physical_sector_bytes": physical,
        "alignment_bytes": alignment,
        "gpt_first_usable_bytes": first_usable,
        "gpt_last_usable_exclusive_bytes": last_usable_exclusive,
        "allocated_bytes": sum(item["size_bytes"] for item in partitions),
        "unallocated_bytes": last_usable_exclusive - cursor,
        "partitions": partitions,
    }


def _validate_btrfs_subvolumes(request: StorageRequestV2) -> list[dict[str, str]]:
    if not request.subvolumes or request.subvolumes[0] != "@":
        raise StoragePlanningError("Btrfs root subvolume @ is required and must be first")
    if len(set(request.subvolumes)) != len(request.subvolumes):
        raise StoragePlanningError("Btrfs subvolume names must be unique")
    unknown = sorted(set(request.subvolumes) - set(SUPPORTED_BTRFS_SUBVOLUMES))
    if unknown:
        raise StoragePlanningError(f"unsupported Btrfs subvolumes: {unknown}")
    wants_home = request.layout in {"separate-home", "root-home-swap"}
    if ("@home" in request.subvolumes) != wants_home:
        raise StoragePlanningError("Btrfs @home selection must match the chosen layout")
    mounts = [SUPPORTED_BTRFS_SUBVOLUMES[name] for name in request.subvolumes]
    if len(set(mounts)) != len(mounts):
        raise StoragePlanningError("Btrfs subvolume mount points must be unique")
    return [
        {"name": name, "mount_point": SUPPORTED_BTRFS_SUBVOLUMES[name]}
        for name in request.subvolumes
    ]


def plan_storage_v2(disk_size_bytes: int, request: StorageRequestV2) -> dict[str, Any]:
    """Return a deterministic single-filesystem Btrfs layout with optional swap."""
    disk_size = _positive_integer(disk_size_bytes, "target size_bytes")
    logical = _positive_integer(request.logical_sector_bytes, "logical sector size")
    physical = _positive_integer(request.physical_sector_bytes, "physical sector size")
    if request.schema_version != STORAGE_SCHEMA_V2:
        raise StoragePlanningError(f"unsupported storage schema version: {request.schema_version}")
    if request.filesystem != "btrfs":
        raise StoragePlanningError("storage schema v2 supports only Btrfs")
    if request.layout not in SUPPORTED_LAYOUTS:
        raise StoragePlanningError(f"unsupported storage layout: {request.layout}")
    if request.compression not in SUPPORTED_BTRFS_COMPRESSION:
        raise StoragePlanningError(f"unsupported Btrfs compression: {request.compression}")
    if request.root_size_bytes is not None:
        raise StoragePlanningError("Btrfs subvolumes share the root filesystem capacity")
    subvolumes = _validate_btrfs_subvolumes(request)
    if logical & (logical - 1) or physical & (physical - 1):
        raise StoragePlanningError("sector sizes must be powers of two")
    if logical < 512 or physical < logical or physical % logical:
        raise StoragePlanningError("physical and logical sector sizes are inconsistent")

    alignment = max(DEFAULT_ALIGNMENT_BYTES, physical)
    if alignment % logical:
        alignment = _align_up(alignment, logical)
    entry_array_bytes = _align_up(GPT_ENTRY_COUNT * GPT_ENTRY_BYTES, logical)
    first_usable = _align_up(2 * logical + entry_array_bytes, alignment)
    last_usable_exclusive = _align_down(disk_size - logical - entry_array_bytes, alignment)
    if last_usable_exclusive <= first_usable:
        raise StoragePlanningError("target has no usable GPT-aligned space")

    cursor = first_usable
    partitions = [_partition("esp", cursor, ESP_BYTES, "vfat", "/efi", "esp", "fixed")]
    cursor += ESP_BYTES
    available = last_usable_exclusive - cursor
    wants_swap = request.layout in {"root-swap", "root-home-swap"}
    swap_size = 0
    if wants_swap:
        swap_size = _align_up(request.swap_size_bytes or 2 * GIB, alignment)
        if swap_size < MINIMUM_SWAP_BYTES:
            raise StoragePlanningError("swap must be at least 256 MiB")
    elif request.swap_size_bytes is not None:
        raise StoragePlanningError("swap size requires a layout with swap")
    root_size = _align_down(available - swap_size, alignment)
    if root_size < MINIMUM_ROOT_BYTES:
        raise StoragePlanningError("custom layout leaves less than 5 GiB for root")
    partitions.append(
        _partition("root", cursor, root_size, "btrfs", "/", "root-x86-64", "remaining")
    )
    cursor += root_size
    if wants_swap:
        partitions.append(_partition("swap", cursor, swap_size, "swap", None, "swap", "fixed"))
        cursor += swap_size
    if cursor > last_usable_exclusive:
        raise StoragePlanningError("partition layout exceeds usable target capacity")
    previous_end = first_usable
    for partition in partitions:
        if partition["start_bytes"] < previous_end:
            raise StoragePlanningError("partition layout overlaps")
        if partition["start_bytes"] % alignment or partition["size_bytes"] % alignment:
            raise StoragePlanningError("partition layout is not correctly aligned")
        previous_end = partition["end_bytes"]
    return {
        "schema_version": STORAGE_SCHEMA_V2,
        "layout": request.layout,
        "filesystem": request.filesystem,
        "compression": request.compression,
        "subvolumes": subvolumes,
        "disk_size_bytes": disk_size,
        "logical_sector_bytes": logical,
        "physical_sector_bytes": physical,
        "alignment_bytes": alignment,
        "gpt_first_usable_bytes": first_usable,
        "gpt_last_usable_exclusive_bytes": last_usable_exclusive,
        "allocated_bytes": sum(item["size_bytes"] for item in partitions),
        "unallocated_bytes": last_usable_exclusive - cursor,
        "partitions": partitions,
    }


def _validate_encryption_policy(encryption: EncryptionRequestV1, *, expected_mapper: str) -> None:
    if encryption.schema_version != 1 or encryption.enabled is not True:
        raise StoragePlanningError("storage schema v3 requires enabled encryption policy v1")
    if encryption.luks_version != 2:
        raise StoragePlanningError("only LUKS2 root encryption is supported")
    if encryption.mapper_name != expected_mapper:
        raise StoragePlanningError(f"encrypted mapper must be named {expected_mapper}")
    if encryption.pbkdf != LUKS_PBKDF or encryption.keyslot != 0:
        raise StoragePlanningError("unsupported LUKS2 key derivation or keyslot policy")
    if not 1000 <= encryption.iter_time_ms <= 5000:
        raise StoragePlanningError("LUKS2 iteration time must be between 1000 and 5000 ms")
    if not 65536 <= encryption.pbkdf_memory_kib <= 524288:
        raise StoragePlanningError("LUKS2 Argon2id memory must be between 64 and 512 MiB")
    if not 1 <= encryption.pbkdf_parallel_threads <= 4:
        raise StoragePlanningError("LUKS2 Argon2id parallelism must be between 1 and 4 threads")


def _validate_encryption(request: StorageRequestV3) -> None:
    _validate_encryption_policy(request.encryption, expected_mapper=LUKS_MAPPER_NAME)


def plan_storage_v3(disk_size_bytes: int, request: StorageRequestV3) -> dict[str, Any]:
    """Return a deterministic encrypted whole-root layout without unencrypted data."""
    _validate_encryption(request)
    if request.filesystem not in SUPPORTED_ENCRYPTED_FILESYSTEMS:
        raise StoragePlanningError("encrypted root supports only ext4 or Btrfs")
    if request.layout not in {"standard", "separate-home"}:
        raise StoragePlanningError(
            "encrypted root does not support separate swap or home partitions"
        )
    if request.filesystem == "ext4":
        if request.layout != "standard" or request.subvolumes or request.compression != "none":
            raise StoragePlanningError("encrypted ext4 requires the standard layout")
    else:
        btrfs_request = StorageRequestV2(
            layout=request.layout,
            subvolumes=request.subvolumes,
            compression=request.compression,
            logical_sector_bytes=request.logical_sector_bytes,
            physical_sector_bytes=request.physical_sector_bytes,
        )
        subvolumes = _validate_btrfs_subvolumes(btrfs_request)
    base = plan_storage_v1(
        disk_size_bytes,
        StorageRequestV1(
            layout="standard",
            logical_sector_bytes=request.logical_sector_bytes,
            physical_sector_bytes=request.physical_sector_bytes,
        ),
    )
    root = base["partitions"][1]
    root["filesystem"] = "crypto_LUKS"
    root["inner_filesystem"] = request.filesystem
    root["mapper_name"] = request.encryption.mapper_name
    return {
        **base,
        "schema_version": STORAGE_SCHEMA_V3,
        "layout": request.layout,
        "filesystem": request.filesystem,
        "compression": request.compression,
        "subvolumes": subvolumes if request.filesystem == "btrfs" else [],
        "encryption": request.encryption.to_dict(),
    }


def plan_storage_v4(disk_size_bytes: int, request: StorageRequestV4) -> dict[str, Any]:
    """Plan an explicit ordered manual layout without touching storage."""
    disk_size = _positive_integer(disk_size_bytes, "target size_bytes")
    logical = _positive_integer(request.logical_sector_bytes, "logical sector size")
    physical = _positive_integer(request.physical_sector_bytes, "physical sector size")
    if request.schema_version != STORAGE_SCHEMA_V4:
        raise StoragePlanningError(f"unsupported storage schema version: {request.schema_version}")
    if logical & (logical - 1) or physical & (physical - 1):
        raise StoragePlanningError("sector sizes must be powers of two")
    if logical < 512 or physical < logical or physical % logical:
        raise StoragePlanningError("physical and logical sector sizes are inconsistent")
    if not request.partitions:
        raise StoragePlanningError("manual layout requires partitions")

    roles = [item.role for item in request.partitions]
    unknown_roles = sorted(set(roles) - SUPPORTED_MANUAL_ROLES)
    if unknown_roles:
        raise StoragePlanningError(f"unsupported manual partition roles: {unknown_roles}")
    if len(roles) != len(set(roles)):
        raise StoragePlanningError("manual partition roles must be unique")
    if roles.count("esp") != 1 or roles.count("root") != 1:
        raise StoragePlanningError("manual layout requires exactly one EFI and one root partition")
    remaining = [item for item in request.partitions if item.use_remaining]
    if len(remaining) > 1:
        raise StoragePlanningError("only one manual partition may use remaining space")
    if remaining and remaining[0] is not request.partitions[-1]:
        raise StoragePlanningError("the remaining-space partition must be last")

    root_request = next(item for item in request.partitions if item.role == "root")
    for item in request.partitions:
        allowed_filesystems, mount_point, _partition_type, minimum = MANUAL_ROLE_POLICY[item.role]
        if item.filesystem not in allowed_filesystems or item.mount_point != mount_point:
            raise StoragePlanningError(
                f"unsupported {item.role} filesystem or mount point: "
                f"{item.filesystem} {item.mount_point}"
            )
        if item.use_remaining:
            if item.size_bytes is not None:
                raise StoragePlanningError("remaining-space partition cannot also specify a size")
        else:
            size = _positive_integer(item.size_bytes, f"{item.role} size")
            if size < minimum:
                raise StoragePlanningError(f"{item.role} must be at least {minimum // MIB} MiB")
        if item.role == "esp" and (item.use_remaining or item.size_bytes != ESP_BYTES):
            raise StoragePlanningError("EFI System Partition must be exactly 260 MiB")

    if request.compression not in SUPPORTED_BTRFS_COMPRESSION:
        raise StoragePlanningError(f"unsupported Btrfs compression: {request.compression}")
    if root_request.filesystem == "btrfs":
        layout = "separate-home" if "@home" in request.subvolumes else "standard"
        subvolumes = _validate_btrfs_subvolumes(
            StorageRequestV2(
                layout=layout,
                subvolumes=request.subvolumes,
                compression=request.compression,
            )
        )
        if "home" in roles and "@home" in request.subvolumes:
            raise StoragePlanningError("/home cannot be both a partition and a Btrfs subvolume")
    else:
        if request.subvolumes or request.compression != "none":
            raise StoragePlanningError("ext4 manual root cannot configure Btrfs options")
        subvolumes = []

    if request.encryption is not None:
        _validate_encryption(
            StorageRequestV3(filesystem=root_request.filesystem, encryption=request.encryption)
        )
        if set(roles) != {"esp", "root"}:
            raise StoragePlanningError(
                "encrypted manual layouts support only EFI and encrypted root; "
                "use Btrfs subvolumes for home data"
            )

    alignment = max(DEFAULT_ALIGNMENT_BYTES, physical)
    if alignment % logical:
        alignment = _align_up(alignment, logical)
    entry_array_bytes = _align_up(GPT_ENTRY_COUNT * GPT_ENTRY_BYTES, logical)
    first_usable = _align_up(2 * logical + entry_array_bytes, alignment)
    last_usable_exclusive = _align_down(disk_size - logical - entry_array_bytes, alignment)
    if last_usable_exclusive <= first_usable:
        raise StoragePlanningError("target has no usable GPT-aligned space")
    cursor = first_usable
    partitions: list[dict[str, Any]] = []
    fixed_after = sum(
        _align_up(int(item.size_bytes), alignment)
        for item in request.partitions
        if not item.use_remaining
    )
    for item in request.partitions:
        _, _, partition_type, minimum = MANUAL_ROLE_POLICY[item.role]
        if item.use_remaining:
            size = _align_down(last_usable_exclusive - cursor, alignment)
        else:
            size = _align_up(int(item.size_bytes), alignment)
            fixed_after -= size
        if size < minimum:
            raise StoragePlanningError(f"manual layout leaves insufficient space for {item.role}")
        if cursor + size + fixed_after > last_usable_exclusive:
            raise StoragePlanningError("manual partition layout exceeds usable target capacity")
        filesystem = item.filesystem
        partition = _partition(
            item.role,
            cursor,
            size,
            "crypto_LUKS" if item.role == "root" and request.encryption else filesystem,
            item.mount_point,
            partition_type,
            "remaining" if item.use_remaining else "fixed",
        )
        if item.role == "root" and request.encryption:
            partition["inner_filesystem"] = filesystem
            partition["mapper_name"] = request.encryption.mapper_name
        partitions.append(partition)
        cursor += size

    return {
        "schema_version": STORAGE_SCHEMA_V4,
        "layout": "manual",
        "filesystem": root_request.filesystem,
        "compression": request.compression,
        "subvolumes": subvolumes,
        "disk_size_bytes": disk_size,
        "logical_sector_bytes": logical,
        "physical_sector_bytes": physical,
        "alignment_bytes": alignment,
        "gpt_first_usable_bytes": first_usable,
        "gpt_last_usable_exclusive_bytes": last_usable_exclusive,
        "allocated_bytes": sum(item["size_bytes"] for item in partitions),
        "unallocated_bytes": last_usable_exclusive - cursor,
        "partitions": partitions,
        **({"encryption": request.encryption.to_dict()} if request.encryption else {}),
    }


def _valid_lvm_name(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 63:
        raise StoragePlanningError(f"{field} must contain 1 to 63 characters")
    if not value[0].isalnum() or any(not (char.isalnum() or char == "_") for char in value):
        raise StoragePlanningError(f"{field} must use letters, numbers, and underscores")
    if value in {".", "..", "snapshot", "pvmove"}:
        raise StoragePlanningError(f"unsupported {field}: {value}")
    return value


def _plan_lvm_storage(
    disk_size_bytes: int,
    request: StorageRequestV5 | StorageRequestV6,
    *,
    encryption: EncryptionRequestV1 | None,
) -> dict[str, Any]:
    """Plan one deterministic LVM hierarchy, optionally inside LUKS2."""
    disk_size = _positive_integer(disk_size_bytes, "target size_bytes")
    logical = _positive_integer(request.logical_sector_bytes, "logical sector size")
    physical = _positive_integer(request.physical_sector_bytes, "physical sector size")
    expected_schema = STORAGE_SCHEMA_V6 if encryption else STORAGE_SCHEMA_V5
    if request.schema_version != expected_schema:
        raise StoragePlanningError(f"unsupported storage schema version: {request.schema_version}")
    if encryption:
        _validate_encryption_policy(encryption, expected_mapper=LUKS_LVM_MAPPER_NAME)
    if logical & (logical - 1) or physical & (physical - 1):
        raise StoragePlanningError("sector sizes must be powers of two")
    if logical < 512 or physical < logical or physical % logical:
        raise StoragePlanningError("physical and logical sector sizes are inconsistent")
    vg_name = _valid_lvm_name(request.volume_group, "volume group name")
    extent = _positive_integer(request.extent_size_bytes, "LVM physical extent size")
    if extent < MIB or extent > GIB or extent & (extent - 1):
        raise StoragePlanningError(
            "LVM physical extent size must be a power of two from 1 MiB to 1 GiB"
        )
    if not request.logical_volumes:
        raise StoragePlanningError("LVM layout requires logical volumes")
    roles = [item.role for item in request.logical_volumes]
    names = [item.name for item in request.logical_volumes]
    unknown = sorted(set(roles) - SUPPORTED_LVM_ROLES)
    if unknown:
        raise StoragePlanningError(f"unsupported LVM logical-volume roles: {unknown}")
    if len(roles) != len(set(roles)):
        raise StoragePlanningError("LVM logical-volume roles must be unique")
    if len(names) != len(set(names)):
        raise StoragePlanningError("LVM logical-volume names must be unique")
    if roles.count("root") != 1:
        raise StoragePlanningError("LVM layout requires exactly one root logical volume")
    remaining = [item for item in request.logical_volumes if item.use_remaining]
    if len(remaining) > 1:
        raise StoragePlanningError("only one logical volume may use remaining VG space")
    if remaining and remaining[0] is not request.logical_volumes[-1]:
        raise StoragePlanningError("the remaining-space logical volume must be last")
    mount_points: set[str] = set()
    for item in request.logical_volumes:
        _valid_lvm_name(item.name, "logical volume name")
        allowed_filesystems, mount_point, minimum = LVM_ROLE_POLICY[item.role]
        if item.filesystem not in allowed_filesystems or item.mount_point != mount_point:
            raise StoragePlanningError(
                f"unsupported {item.role} logical-volume filesystem or mount point: "
                f"{item.filesystem} {item.mount_point}"
            )
        if mount_point is not None:
            if mount_point in mount_points:
                raise StoragePlanningError(f"duplicate mount point: {mount_point}")
            mount_points.add(mount_point)
        if item.use_remaining:
            if item.size_bytes is not None:
                raise StoragePlanningError("remaining-space logical volume cannot specify a size")
        else:
            size = _positive_integer(item.size_bytes, f"{item.role} logical-volume size")
            if size < minimum:
                raise StoragePlanningError(
                    f"{item.role} logical volume must be at least {minimum // MIB} MiB"
                )

    # Physical extents are allocated inside the PV and do not constrain the
    # GPT partition start. Keep the established whole-disk alignment policy so
    # systemd-repart can materialize the authoritative boundaries exactly.
    alignment = max(DEFAULT_ALIGNMENT_BYTES, physical)
    if alignment % logical:
        alignment = _align_up(alignment, logical)
    entry_array_bytes = _align_up(GPT_ENTRY_COUNT * GPT_ENTRY_BYTES, logical)
    first_usable = _align_up(2 * logical + entry_array_bytes, alignment)
    last_usable_exclusive = _align_down(disk_size - logical - entry_array_bytes, alignment)
    cursor = first_usable
    esp = _partition("esp", cursor, ESP_BYTES, "vfat", "/efi", "esp", "fixed")
    cursor += ESP_BYTES
    pv_size = _align_down(last_usable_exclusive - cursor, alignment)
    if pv_size <= 0:
        raise StoragePlanningError("target has no capacity for an LVM physical volume")
    pv = _partition(
        "lvm-pv",
        cursor,
        pv_size,
        "crypto_LUKS" if encryption else "LVM2_member",
        None,
        "linux-generic",
        "remaining",
    )
    if encryption:
        pv["inner_filesystem"] = "LVM2_member"
        pv["mapper_name"] = encryption.mapper_name
    lvm_capacity = pv_size - (LUKS2_METADATA_BYTES if encryption else 0)
    total_extents = lvm_capacity // extent
    usable_extents = total_extents - LVM_METADATA_EXTENTS
    if usable_extents <= 0:
        raise StoragePlanningError("LVM physical volume has no usable extents")
    fixed_extents = sum(
        _align_up(int(item.size_bytes), extent) // extent
        for item in request.logical_volumes
        if not item.use_remaining
    )
    if fixed_extents > usable_extents:
        raise StoragePlanningError("logical volumes exceed available VG extents")
    volumes: list[dict[str, Any]] = []
    allocated_extents = 0
    for item in request.logical_volumes:
        extents = (
            usable_extents - allocated_extents
            if item.use_remaining
            else (_align_up(int(item.size_bytes), extent) // extent)
        )
        minimum = LVM_ROLE_POLICY[item.role][2]
        if extents * extent < minimum:
            raise StoragePlanningError(
                f"LVM layout leaves insufficient space for {item.role} logical volume"
            )
        if allocated_extents + extents > usable_extents:
            raise StoragePlanningError("logical volumes exceed available VG extents")
        volumes.append(
            {
                "name": item.name,
                "role": item.role,
                "filesystem": item.filesystem,
                "mount_point": item.mount_point,
                "size_bytes": extents * extent,
                "extent_count": extents,
                "size_policy": "remaining" if item.use_remaining else "fixed",
                "device": f"/dev/{vg_name}/{item.name}",
                "mapper_device": f"/dev/mapper/{vg_name}-{item.name}",
            }
        )
        allocated_extents += extents
    free_extents = usable_extents - allocated_extents
    return {
        "schema_version": expected_schema,
        "layout": "lvm",
        "filesystem": "ext4",
        "disk_size_bytes": disk_size,
        "logical_sector_bytes": logical,
        "physical_sector_bytes": physical,
        "alignment_bytes": alignment,
        "gpt_first_usable_bytes": first_usable,
        "gpt_last_usable_exclusive_bytes": last_usable_exclusive,
        "allocated_bytes": ESP_BYTES + pv_size,
        "unallocated_bytes": last_usable_exclusive - (cursor + pv_size),
        "partitions": [esp, pv],
        **({"encryption": encryption.to_dict()} if encryption else {}),
        "lvm": {
            "volume_group": vg_name,
            "extent_size_bytes": extent,
            "metadata_extents": LVM_METADATA_EXTENTS,
            "total_extents": total_extents,
            "usable_extents": usable_extents,
            "allocated_extents": allocated_extents,
            "free_extents": free_extents,
            "free_bytes": free_extents * extent,
            "physical_volume_role": "lvm-pv",
            "container_overhead_bytes": LUKS2_METADATA_BYTES if encryption else 0,
            "logical_volumes": volumes,
        },
    }


def plan_storage_v5(disk_size_bytes: int, request: StorageRequestV5) -> dict[str, Any]:
    """Plan a deterministic EFI + single-PV LVM2 installation."""
    return _plan_lvm_storage(disk_size_bytes, request, encryption=None)


def plan_storage_v6(disk_size_bytes: int, request: StorageRequestV6) -> dict[str, Any]:
    """Plan deterministic LVM2 inside an interactive LUKS2 container."""
    return _plan_lvm_storage(disk_size_bytes, request, encryption=request.encryption)


def plan_storage_v7(disk_size_bytes: int, request: StorageRequestV7) -> dict[str, Any]:
    """Plan incremental GPT changes without moving or deleting existing partitions."""
    disk_size = _positive_integer(disk_size_bytes, "target size_bytes")
    logical = _positive_integer(request.logical_sector_bytes, "logical sector size")
    physical = _positive_integer(request.physical_sector_bytes, "physical sector size")
    if request.schema_version != STORAGE_SCHEMA_V7:
        raise StoragePlanningError(f"unsupported storage schema version: {request.schema_version}")
    if logical & (logical - 1) or physical & (physical - 1):
        raise StoragePlanningError("sector sizes must be powers of two")
    if logical < 512 or physical < logical or physical % logical:
        raise StoragePlanningError("physical and logical sector sizes are inconsistent")
    if not request.existing_partitions:
        raise StoragePlanningError("preservation mode requires an observed existing GPT")

    alignment = max(DEFAULT_ALIGNMENT_BYTES, physical)
    if alignment % logical:
        alignment = _align_up(alignment, logical)
    entry_array_bytes = _align_up(GPT_ENTRY_COUNT * GPT_ENTRY_BYTES, logical)
    first_usable = _align_up(2 * logical + entry_array_bytes, alignment)
    last_usable_exclusive = _align_down(disk_size - logical - entry_array_bytes, alignment)

    numbers: set[int] = set()
    identities: set[str] = set()
    existing_rows: list[dict[str, Any]] = []
    previous_end = first_usable
    for item in sorted(request.existing_partitions, key=lambda value: value.start_bytes):
        number = _positive_integer(item.number, "existing partition number")
        start = _positive_integer(item.start_bytes, "existing partition start")
        size = _positive_integer(item.size_bytes, "existing partition size")
        if number in numbers:
            raise StoragePlanningError("existing partition numbers must be unique")
        if not item.partition_uuid or item.partition_uuid.lower() in identities:
            raise StoragePlanningError("existing partition UUIDs must be present and unique")
        if start < first_usable or start + size > last_usable_exclusive:
            raise StoragePlanningError("existing partition lies outside usable GPT space")
        if start < previous_end:
            raise StoragePlanningError("existing GPT partitions overlap")
        if start % logical or size % logical:
            raise StoragePlanningError("existing partition boundaries are not sector aligned")
        if item.action not in {"preserve", "reuse", "format"}:
            raise StoragePlanningError(f"unsupported existing partition action: {item.action}")
        if item.action == "preserve" and (item.role is not None or item.format_as is not None):
            raise StoragePlanningError("preserved partitions cannot have an installation role")
        if item.action == "reuse":
            if item.role != "esp" or item.filesystem != "vfat" or item.format_as is not None:
                raise StoragePlanningError("only a compatible vfat EFI partition may be reused")
            if item.partition_type.lower() not in {
                "esp",
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            }:
                raise StoragePlanningError("reused EFI partition has the wrong GPT type")
        if item.action == "format" and (
            item.role != "root" or item.format_as not in {"ext4", "btrfs"}
        ):
            raise StoragePlanningError(
                "only an explicitly selected ext4 or Btrfs root may be formatted"
            )
        numbers.add(number)
        identities.add(item.partition_uuid.lower())
        existing_rows.append(
            {
                "partition_number": number,
                "role": item.role or f"preserved-{number}",
                "start_bytes": start,
                "size_bytes": size,
                "end_bytes": start + size,
                "size_policy": "existing",
                "partition_type": item.partition_type,
                "partition_uuid": item.partition_uuid,
                "filesystem": item.format_as if item.action == "format" else item.filesystem,
                "observed_filesystem": item.filesystem,
                "filesystem_uuid": item.filesystem_uuid,
                "label": item.label,
                "mount_point": "/efi"
                if item.role == "esp"
                else "/"
                if item.role == "root"
                else None,
                "action": item.action,
                "existing": True,
            }
        )
        previous_end = start + size

    new_roles = [item.role for item in request.new_partitions]
    if len(new_roles) != len(set(new_roles)):
        raise StoragePlanningError("new preservation partition roles must be unique")
    if set(new_roles) - {"esp", "root", "swap"}:
        raise StoragePlanningError(
            "preservation mode supports only new EFI, root, and swap partitions"
        )
    root_count = sum(item.get("role") == "root" for item in existing_rows) + new_roles.count("root")
    esp_count = sum(item.get("role") == "esp" for item in existing_rows) + new_roles.count("esp")
    if root_count != 1 or esp_count != 1:
        raise StoragePlanningError(
            "preservation mode requires exactly one EFI and one root partition"
        )
    if sum(item.use_remaining for item in request.new_partitions) > 1:
        raise StoragePlanningError("only one new partition may use remaining free space")

    root_filesystem = next(
        (row["filesystem"] for row in existing_rows if row["role"] == "root"),
        next((item.filesystem for item in request.new_partitions if item.role == "root"), None),
    )
    if root_filesystem not in {"ext4", "btrfs"}:
        raise StoragePlanningError("preservation root filesystem must be ext4 or Btrfs")
    if request.compression not in SUPPORTED_BTRFS_COMPRESSION:
        raise StoragePlanningError(f"unsupported Btrfs compression: {request.compression}")
    if root_filesystem == "btrfs":
        layout = "separate-home" if "@home" in request.subvolumes else "standard"
        subvolumes = _validate_btrfs_subvolumes(
            StorageRequestV2(
                layout=layout,
                subvolumes=request.subvolumes,
                compression=request.compression,
            )
        )
    else:
        if request.subvolumes or request.compression != "none":
            raise StoragePlanningError("ext4 preservation root cannot configure Btrfs options")
        subvolumes = []

    occupied = sorted((row["start_bytes"], row["end_bytes"]) for row in existing_rows)
    free: list[list[int]] = []
    cursor = first_usable
    for start, end in occupied:
        free_start = _align_up(cursor, alignment)
        free_end = _align_down(start, alignment)
        if free_end > free_start:
            free.append([free_start, free_end])
        cursor = max(cursor, end)
    free_start = _align_up(cursor, alignment)
    if last_usable_exclusive > free_start:
        free.append([free_start, last_usable_exclusive])

    new_rows: list[dict[str, Any]] = []
    next_number = 1
    for item in request.new_partitions:
        allowed, mount, partition_type, minimum = MANUAL_ROLE_POLICY[item.role]
        if item.filesystem not in allowed or item.mount_point != mount:
            raise StoragePlanningError(
                f"unsupported {item.role} filesystem or mount point: {item.filesystem} {item.mount_point}"
            )
        if item.role == "esp" and (
            item.use_remaining or item.size_bytes != ESP_BYTES or item.filesystem != "vfat"
        ):
            raise StoragePlanningError("new EFI System Partition must be exactly 260 MiB")
        if item.use_remaining:
            if item.size_bytes is not None:
                raise StoragePlanningError("remaining-space partition cannot also specify a size")
            candidates = sorted(free, key=lambda extent: (-(extent[1] - extent[0]), extent[0]))
            if not candidates:
                raise StoragePlanningError("no usable unallocated space remains")
            chosen = candidates[0]
            size = _align_down(chosen[1] - chosen[0], alignment)
        else:
            size = _align_up(_positive_integer(item.size_bytes, f"{item.role} size"), alignment)
            chosen = next((extent for extent in free if extent[1] - extent[0] >= size), None)
            if chosen is None:
                raise StoragePlanningError(
                    f"no unallocated region can fit the new {item.role} partition"
                )
        if size < minimum:
            raise StoragePlanningError(f"{item.role} must be at least {minimum // MIB} MiB")
        start = chosen[0]
        chosen[0] += size
        free[:] = [extent for extent in free if extent[1] > extent[0]]
        while next_number in numbers:
            next_number += 1
        number = next_number
        numbers.add(number)
        new_rows.append(
            {
                **_partition(
                    item.role,
                    start,
                    size,
                    item.filesystem,
                    item.mount_point,
                    partition_type,
                    "remaining" if item.use_remaining else "fixed",
                ),
                "partition_number": number,
                "action": "create",
                "existing": False,
            }
        )

    partitions = sorted(existing_rows + new_rows, key=lambda row: row["start_bytes"])
    unallocated = sum(end - start for start, end in free)
    return {
        "schema_version": STORAGE_SCHEMA_V7,
        "layout": "preserve",
        "filesystem": root_filesystem,
        "compression": request.compression,
        "subvolumes": subvolumes,
        "disk_size_bytes": disk_size,
        "logical_sector_bytes": logical,
        "physical_sector_bytes": physical,
        "alignment_bytes": alignment,
        "gpt_first_usable_bytes": first_usable,
        "gpt_last_usable_exclusive_bytes": last_usable_exclusive,
        "allocated_bytes": sum(item["size_bytes"] for item in partitions),
        "unallocated_bytes": unallocated,
        "partitions": partitions,
        "preservation": {
            "existing_partition_count": len(existing_rows),
            "preserved_partition_numbers": [
                row["partition_number"] for row in existing_rows if row["action"] == "preserve"
            ],
            "reused_partition_numbers": [
                row["partition_number"] for row in existing_rows if row["action"] == "reuse"
            ],
            "formatted_partition_numbers": [
                row["partition_number"] for row in existing_rows if row["action"] == "format"
            ],
            "created_partition_numbers": [row["partition_number"] for row in new_rows],
        },
    }


def plan_storage(disk_size_bytes: int, request: StorageRequest) -> dict[str, Any]:
    if isinstance(request, StorageRequestV7):
        return plan_storage_v7(disk_size_bytes, request)
    if isinstance(request, StorageRequestV6):
        return plan_storage_v6(disk_size_bytes, request)
    if isinstance(request, StorageRequestV5):
        return plan_storage_v5(disk_size_bytes, request)
    if isinstance(request, StorageRequestV4):
        return plan_storage_v4(disk_size_bytes, request)
    if isinstance(request, StorageRequestV3):
        return plan_storage_v3(disk_size_bytes, request)
    if isinstance(request, StorageRequestV2):
        return plan_storage_v2(disk_size_bytes, request)
    return plan_storage_v1(disk_size_bytes, request)
