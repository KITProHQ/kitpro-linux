"""Side-effect-free KITPro installation planning.

This module deliberately imports only the Python standard library. Callers must
perform hardware discovery, source verification, and secret collection before
constructing a request.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .inventory import evaluate_storage_eligibility
from .storage import (
    StoragePlanningError,
    StorageRequestV1,
    StorageRequestV3,
    StorageRequestV4,
    StorageRequestV5,
    StorageRequestV6,
    StorageRequestV7,
    plan_storage,
    storage_request_from_dict,
)

API_VERSION = 1
PLAN_SCHEMA_VERSION = 1
PLANNER_VERSION = "1.8.0"
AUTHORITATIVE_INSTALLER_VERSION = "0.8.0-dev.19"
GIB = 1024**3
ESP_SIZE_BYTES = 256 * 1024**2
PARTITION_OVERHEAD_BYTES = 2 * 1024**2
ROOTFS_ESTIMATE_BYTES = 3 * GIB
MINIMUM_FREE_RESERVE_BYTES = 2 * GIB
RECOMMENDED_MINIMUM_BYTES = 12 * GIB
SUPPORTED_ARCHITECTURE = "x86_64"
SUPPORTED_PARTITION_TABLE = "gpt"
SUPPORTED_ESP_FILESYSTEM = "vfat"
SUPPORTED_ROOT_FILESYSTEM = "ext4"
SUPPORTED_ROOT_FILESYSTEMS = {"ext4", "btrfs"}
SUPPORTED_BOOT_MODE = "uefi"
SUPPORTED_BOOTLOADER = "systemd-boot"
SUPPORTED_KERNEL = "linux-lts"
NETWORK_INTERFACE_MATCH = "en*"
PLAN_NAMESPACE = uuid.UUID("1b28362f-69f8-4eb1-984c-c35cd5578257")
PUBLIC_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
}


class PlanningError(ValueError):
    """The explicit planning inputs are invalid or unsupported."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the stable UTF-8 JSON representation used for all digests."""
    # This byte form is part of the released backend's hash contract.
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_document(value: Any) -> str:
    return _sha256_bytes(canonical_json_bytes(value))


@dataclass(frozen=True, slots=True)
class SourceFactsV1:
    """Verified, non-secret facts about an offline installation source."""

    release: str
    generation: str
    generation_manifest_sha256: str
    artifact_set_sha256: str
    package_count: int
    source: str
    rootfs_profile_sha256: str

    def validate(self) -> None:
        if not re.fullmatch(r"[0-9]+\.[0-9]+(?:-dev)?", self.release):
            raise PlanningError("source release has an unsupported format")
        if not re.fullmatch(re.escape(self.release) + r"-g[0-9]{4}", self.generation):
            raise PlanningError("source generation does not belong to its release")
        for name, value in (
            ("generation_manifest_sha256", self.generation_manifest_sha256),
            ("artifact_set_sha256", self.artifact_set_sha256),
            ("rootfs_profile_sha256", self.rootfs_profile_sha256),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise PlanningError(f"source {name} must be a SHA-256 digest")
        if not isinstance(self.package_count, int) or isinstance(self.package_count, bool):
            raise PlanningError("source package_count must be an integer")
        if self.package_count < 1:
            raise PlanningError("source package_count must be positive")
        if not self.source:
            raise PlanningError("source location must be explicit")

    def to_dict(self) -> dict[str, Any]:
        return {
            "release": self.release,
            "generation": self.generation,
            "generation_manifest_sha256": self.generation_manifest_sha256,
            "artifact_set_sha256": self.artifact_set_sha256,
            "package_count": self.package_count,
            "source": self.source,
            "rootfs_profile_sha256": self.rootfs_profile_sha256,
        }


KITPRO_LINUX_1_0_SOURCE = SourceFactsV1(
    release="1.0",
    generation="1.0-g0002",
    generation_manifest_sha256=("fb20ff778fd2c4fcbd5cef72809d3104dcb5f0d81c196c708f0825cf60ee3585"),
    artifact_set_sha256=("bbc64a7dc0fb1fe38d0b9570901913d22eec51ac6d49196e8c6d677e5baa1743"),
    package_count=199,
    source="repo/stable/1.0/1.0-g0002",
    rootfs_profile_sha256=("b1a467754e637b90be57c18725a982c48745a0ef6a1ae4baee8da169fa6e0d8d"),
)


@dataclass(frozen=True, slots=True)
class PlanningRequestV1:
    """All desired state and observed facts required by planner API v1."""

    install_spec: Mapping[str, Any]
    target: Mapping[str, Any]
    source: SourceFactsV1
    installer_version: str
    api_version: int = API_VERSION


@dataclass(frozen=True, slots=True)
class PlanningResultV1:
    """Canonical backend plan plus the complete ordered operation model."""

    plan: dict[str, Any]
    operations: tuple[dict[str, Any], ...]
    result_sha256: str
    api_version: int = API_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "api_version": self.api_version,
            "plan": self.plan,
            "operations": [dict(operation) for operation in self.operations],
            "result_sha256": self.result_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def validate(self) -> None:
        if self.api_version != API_VERSION:
            raise PlanningError(f"unsupported planning API version: {self.api_version}")
        validate_plan_document(self.plan)
        orders = [operation.get("order") for operation in self.operations]
        if orders != list(range(1, len(self.operations) + 1)):
            raise PlanningError("installation operations are not sequential")
        unsigned = {
            "api_version": self.api_version,
            "plan": self.plan,
            "operations": [dict(operation) for operation in self.operations],
        }
        if self.result_sha256 != _sha256_document(unsigned):
            raise PlanningError("planning result hash does not match its content")


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PlanningError(f"{field} must be an object")
    return dict(value)


def _exact_keys(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise PlanningError(f"{field} contains unsupported fields: {unknown}")


def _required_string(value: Mapping[str, Any], key: str, field: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise PlanningError(f"{field}.{key} must be a non-empty string")
    return result


def _validated_spec(value: Mapping[str, Any]) -> dict[str, Any]:
    spec = _mapping(value, "installation specification")
    _exact_keys(
        spec,
        {
            "version",
            "release",
            "system",
            "disk",
            "network",
            "administrator",
            "ssh",
            "firewall",
            "boot",
        },
        "installation specification",
    )
    if spec.get("version") != 1:
        raise PlanningError(
            f"unsupported installation specification version: {spec.get('version')}"
        )
    release = _mapping(spec.get("release"), "release")
    name = _required_string(release, "name", "release")
    generation = _required_string(release, "generation", "release")
    if not re.fullmatch(re.escape(name) + r"-g[0-9]{4}", generation):
        raise PlanningError("release.generation does not belong to release.name")

    system = _mapping(spec.get("system"), "system")
    hostname = _required_string(system, "hostname", "system")
    if not re.fullmatch(r"(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", hostname):
        raise PlanningError("system.hostname is not a valid single-label hostname")
    if system.get("locale") not in {"C.UTF-8", "en_US.UTF-8"}:
        raise PlanningError(f"unsupported system.locale: {system.get('locale')}")
    _required_string(system, "timezone", "system")

    disk = _mapping(spec.get("disk"), "disk")
    layout = disk.get("layout")
    if layout not in {
        "standard",
        "separate-home",
        "root-swap",
        "root-home-swap",
        "manual",
        "lvm",
        "preserve",
    }:
        raise PlanningError(f"unsupported disk.layout: {layout}")
    if disk.get("filesystem") not in SUPPORTED_ROOT_FILESYSTEMS:
        raise PlanningError(f"unsupported root filesystem: {disk.get('filesystem')}")
    try:
        storage = storage_request_from_dict(disk.get("storage"))
    except StoragePlanningError as error:
        raise PlanningError(str(error)) from error
    if layout == "standard" and "storage" not in disk:
        storage = StorageRequestV1()
    elif isinstance(storage, StorageRequestV4) and layout != "manual":
        raise PlanningError("manual storage schema requires disk.layout manual")
    elif isinstance(storage, (StorageRequestV5, StorageRequestV6)) and layout != "lvm":
        raise PlanningError("LVM storage schema requires disk.layout lvm")
    elif isinstance(storage, StorageRequestV7) and layout != "preserve":
        raise PlanningError("preservation storage schema requires disk.layout preserve")
    elif (
        not isinstance(
            storage, (StorageRequestV4, StorageRequestV5, StorageRequestV6, StorageRequestV7)
        )
        and storage.layout != layout
    ):
        raise PlanningError("disk.layout and disk.storage.layout must match")
    encrypted = (
        isinstance(storage, StorageRequestV3)
        or (isinstance(storage, StorageRequestV4) and storage.encryption is not None)
        or isinstance(storage, StorageRequestV6)
    )
    requested_root_filesystem = (
        next(item.filesystem for item in storage.partitions if item.role == "root")
        if isinstance(storage, StorageRequestV4)
        else next(
            (
                getattr(item, "format_as", None) or item.filesystem
                for item in (*storage.existing_partitions, *storage.new_partitions)
                if item.role == "root"
            ),
            None,
        )
        if isinstance(storage, StorageRequestV7)
        else "ext4"
        if isinstance(storage, (StorageRequestV5, StorageRequestV6))
        else getattr(storage, "filesystem", None)
    )
    if disk.get("filesystem") == "btrfs" and requested_root_filesystem != "btrfs":
        raise PlanningError("Btrfs requires a filesystem-aware storage schema")
    if disk.get("filesystem") == "ext4" and not isinstance(
        storage,
        (
            StorageRequestV1,
            StorageRequestV3,
            StorageRequestV4,
            StorageRequestV5,
            StorageRequestV6,
            StorageRequestV7,
        ),
    ):
        raise PlanningError("ext4 requires storage schema version 1 or encrypted schema version 3")
    storage_filesystem = requested_root_filesystem or "ext4"
    if encrypted and storage_filesystem != disk.get("filesystem"):
        raise PlanningError("encrypted storage filesystem differs from disk.filesystem")
    if disk.get("target_type") not in {"image", "block"}:
        raise PlanningError(f"unsupported disk.target_type: {disk.get('target_type')}")
    minimum_bytes = disk.get("minimum_capacity_bytes")
    if (
        not isinstance(minimum_bytes, int)
        or isinstance(minimum_bytes, bool)
        or minimum_bytes < 6 * GIB
    ):
        raise PlanningError("disk.minimum_capacity_bytes must be an integer of at least 6 GiB")

    boot = _mapping(spec.get("boot"), "boot")
    if boot.get("mode") != SUPPORTED_BOOT_MODE:
        raise PlanningError(f"unsupported boot.mode: {boot.get('mode')}")
    network = _mapping(spec.get("network"), "network")
    _validate_network(network)
    administrator = _mapping(spec.get("administrator"), "administrator")
    username = _required_string(administrator, "username", "administrator")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", username) or username in {"root", "nobody"}:
        raise PlanningError("administrator.username is not supported")
    keys = administrator.get("ssh_authorized_keys", [])
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
        raise PlanningError("administrator.ssh_authorized_keys must be an array")
    for key in keys:
        fields = key.split()
        if (
            "PRIVATE KEY" in key
            or "\n" in key
            or "\r" in key
            or len(fields) < 2
            or fields[0] not in PUBLIC_KEY_TYPES
            or not re.fullmatch(r"[A-Za-z0-9+/=]+", fields[1])
        ):
            raise PlanningError("administrator SSH key is not a supported public key")
    ssh = _mapping(spec.get("ssh"), "ssh")
    firewall = _mapping(spec.get("firewall"), "firewall")
    if not isinstance(ssh.get("enabled"), bool) or not isinstance(firewall.get("ssh"), bool):
        raise PlanningError("SSH and firewall policy flags must be booleans")
    if ssh["enabled"] != firewall["ssh"]:
        raise PlanningError("SSH service and firewall access must be enabled together")
    if ssh["enabled"] and not keys:
        raise PlanningError("SSH requires at least one administrator public key")
    return spec


def _validate_network(network: Mapping[str, Any]) -> None:
    mode = network.get("mode")
    if mode not in {"dhcp", "static"}:
        raise PlanningError(f"unsupported network.mode: {mode}")
    address = network.get("address")
    prefix = network.get("prefix")
    gateway = network.get("gateway")
    dns = network.get("dns", [])
    if not isinstance(dns, list) or not all(isinstance(item, str) for item in dns):
        raise PlanningError("network.dns must be an array of IPv4 addresses")
    if mode == "dhcp":
        if any(item is not None for item in (address, prefix, gateway)) or dns:
            raise PlanningError("DHCP network configuration cannot contain static fields")
        return
    if not isinstance(prefix, int) or isinstance(prefix, bool) or not 1 <= prefix <= 32:
        raise PlanningError("static network prefix must be between 1 and 32")
    if not isinstance(address, str) or not isinstance(gateway, str) or not dns:
        raise PlanningError("static networking requires address, gateway, and DNS")
    try:
        ipaddress.IPv4Address(address)
        ipaddress.IPv4Address(gateway)
        for resolver in dns:
            ipaddress.IPv4Address(resolver)
    except ipaddress.AddressValueError as error:
        raise PlanningError(f"invalid static IPv4 configuration: {error}") from error


def _validated_target(value: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    target = _mapping(value, "target facts")
    required = {
        "path",
        "target_type",
        "size_bytes",
        "identity",
        "mounted_paths",
        "signatures",
        "partition_table",
        "marker_sha256",
        "transport",
        "read_only",
        "stable_ids",
        "protection_reasons",
        "observation_errors",
        "eligibility",
    }
    missing = sorted(required - set(target))
    if missing:
        raise PlanningError(f"target facts miss fields: {missing}")
    disk = spec["disk"]
    if target["path"] != disk["device"] or target["target_type"] != disk["target_type"]:
        raise PlanningError("observed target does not match the installation specification")
    size = target["size_bytes"]
    if not isinstance(size, int) or isinstance(size, bool):
        raise PlanningError("target size_bytes must be an integer")
    if size < disk["minimum_capacity_bytes"]:
        raise PlanningError("selected target has insufficient storage capacity")
    if target["mounted_paths"]:
        raise PlanningError("selected target or a child partition is mounted")
    if (
        target["read_only"] is not True
        and target["read_only"] is not False
        and target["read_only"] is not None
    ):
        raise PlanningError("target read_only must be true, false, or unavailable")
    expected_eligibility = evaluate_storage_eligibility(
        target_type=target["target_type"],
        device_type="disk" if target["target_type"] in {"block", "image"} else "unsupported",
        size_bytes=size,
        minimum_capacity_bytes=disk["minimum_capacity_bytes"],
        identity=_mapping(target["identity"], "target identity"),
        mounted_paths=target["mounted_paths"],
        read_only=target["read_only"],
        protection_reasons=target["protection_reasons"],
        observation_errors=target["observation_errors"],
    ).to_dict()
    if target["eligibility"] != expected_eligibility:
        raise PlanningError("target eligibility does not match the observed device facts")
    if not expected_eligibility["eligible"]:
        raise PlanningError(
            "selected target is ineligible: " + ", ".join(expected_eligibility["rejection_reasons"])
        )
    if not expected_eligibility["requires_destructive_confirmation"]:
        raise PlanningError("selected target lacks an explicit destructive-confirmation policy")
    return target


def plan_v1(request: PlanningRequestV1) -> PlanningResultV1:
    """Build a deterministic plan without observing or changing the host."""
    if request.api_version != API_VERSION:
        raise PlanningError(f"unsupported planning API version: {request.api_version}")
    if not isinstance(request.installer_version, str) or not request.installer_version:
        raise PlanningError("installer_version must be explicit")
    spec = _validated_spec(request.install_spec)
    target = _validated_target(request.target, spec)
    request.source.validate()
    release = spec["release"]
    if (
        request.source.release != release["name"]
        or request.source.generation != release["generation"]
    ):
        raise PlanningError("verified source does not match the installation specification")

    spec_sha256 = _sha256_document(spec)
    seed = canonical_json_bytes(
        {
            "spec_sha256": spec_sha256,
            "target": target,
            "generation_manifest_sha256": request.source.generation_manifest_sha256,
        }
    ).decode()
    esp_uuid = str(uuid.uuid5(PLAN_NAMESPACE, seed + ":esp"))
    root_uuid = str(uuid.uuid5(PLAN_NAMESPACE, seed + ":root"))
    custom_storage = "storage" in spec["disk"]
    if custom_storage:
        try:
            storage_request = storage_request_from_dict(spec["disk"]["storage"])
            if isinstance(storage_request, StorageRequestV7):
                observed = target.get("partitions")
                if not isinstance(observed, list):
                    raise PlanningError("preservation planning requires observed partition facts")
                observed_by_number = {int(item.get("number", 0)): item for item in observed}
                for existing in storage_request.existing_partitions:
                    item = observed_by_number.get(existing.number)
                    expected = {
                        "start_bytes": existing.start_bytes,
                        "size_bytes": existing.size_bytes,
                        "partition_type": existing.partition_type,
                        "partition_uuid": existing.partition_uuid,
                        "filesystem": existing.filesystem,
                        "filesystem_uuid": existing.filesystem_uuid,
                        "filesystem_label": existing.label,
                    }
                    if item is None or any(
                        item.get(key) != value for key, value in expected.items()
                    ):
                        raise PlanningError(
                            f"existing partition {existing.number} differs from observed target facts"
                        )
                if len(observed_by_number) != len(storage_request.existing_partitions):
                    raise PlanningError("preservation request omits observed existing partitions")
            storage_plan = plan_storage(target["size_bytes"], storage_request)
        except StoragePlanningError as error:
            raise PlanningError(str(error)) from error
        for partition in storage_plan["partitions"]:
            role = partition["role"]
            if not partition.get("existing"):
                partition["partition_uuid"] = str(
                    uuid.uuid5(
                        PLAN_NAMESPACE,
                        seed + f":{role}:{partition.get('partition_number', '')}",
                    )
                )
            partition["planned_size_bytes"] = partition["size_bytes"]
            if role == "root":
                partition["minimum_size_bytes"] = 5 * GIB
        partition_table: dict[str, Any] = {
            "type": SUPPORTED_PARTITION_TABLE,
            "storage_schema_version": storage_plan["schema_version"],
            "layout": storage_plan["layout"],
            "logical_sector_bytes": storage_plan["logical_sector_bytes"],
            "physical_sector_bytes": storage_plan["physical_sector_bytes"],
            "alignment_bytes": storage_plan["alignment_bytes"],
            "gpt_first_usable_bytes": storage_plan["gpt_first_usable_bytes"],
            "gpt_last_usable_exclusive_bytes": storage_plan["gpt_last_usable_exclusive_bytes"],
            "allocated_bytes": storage_plan["allocated_bytes"],
            "unallocated_bytes": storage_plan["unallocated_bytes"],
            "partitions": storage_plan["partitions"],
        }
        if storage_plan["schema_version"] in {2, 3, 4, 7}:
            partition_table.update(
                {
                    "filesystem": storage_plan["filesystem"],
                    "compression": storage_plan["compression"],
                    "subvolumes": storage_plan["subvolumes"],
                }
            )
        if storage_plan["schema_version"] == 7:
            partition_table["preservation"] = storage_plan["preservation"]
        if storage_plan["schema_version"] in {3, 4, 6} and "encryption" in storage_plan:
            encryption = dict(storage_plan["encryption"])
            encryption["luks_uuid"] = str(uuid.uuid5(PLAN_NAMESPACE, seed + ":luks-root"))
            encryption["partition_uuid"] = next(
                item["partition_uuid"]
                for item in storage_plan["partitions"]
                if item["role"] == ("lvm-pv" if storage_plan["schema_version"] == 6 else "root")
            )
            partition_table["encryption"] = encryption
        if storage_plan["schema_version"] in {5, 6}:
            partition_table["filesystem"] = "ext4"
            partition_table["lvm"] = storage_plan["lvm"]
            partition_table.update(
                {volume["role"]: volume for volume in storage_plan["lvm"]["logical_volumes"]}
            )
        partition_table.update(
            {partition["role"]: partition for partition in storage_plan["partitions"]}
        )
        root_size = partition_table["root"]["size_bytes"]
    else:
        root_size = target["size_bytes"] - ESP_SIZE_BYTES - PARTITION_OVERHEAD_BYTES
        partition_table = {
            "type": SUPPORTED_PARTITION_TABLE,
            "esp": {
                "size_bytes": ESP_SIZE_BYTES,
                "partition_type": "esp",
                "partition_uuid": esp_uuid,
                "filesystem": SUPPORTED_ESP_FILESYSTEM,
                "mount_point": "/efi",
            },
            "root": {
                "size_policy": "remaining",
                "minimum_size_bytes": 5 * GIB,
                "planned_size_bytes": root_size,
                "partition_type": "root-x86-64",
                "partition_uuid": root_uuid,
                "filesystem": SUPPORTED_ROOT_FILESYSTEM,
                "mount_point": "/",
            },
        }
    reserve = root_size - ROOTFS_ESTIMATE_BYTES
    if reserve < MINIMUM_FREE_RESERVE_BYTES:
        raise PlanningError(f"planned root filesystem reserve is too small: {reserve} bytes")
    network = spec["network"]
    administrator = spec["administrator"]
    source = request.source
    document: dict[str, Any] = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "installer_version": request.installer_version,
        "install_spec_version": spec["version"],
        "install_spec_sha256": spec_sha256,
        "target": target,
        "release": release["name"],
        "repository_generation": release["generation"],
        "repository": {
            "generation_manifest_sha256": source.generation_manifest_sha256,
            "artifact_set_sha256": source.artifact_set_sha256,
            "package_count": source.package_count,
            "source": source.source,
        },
        "rootfs": {
            "profile_sha256": source.rootfs_profile_sha256,
            "estimated_size_bytes": ROOTFS_ESTIMATE_BYTES,
            "minimum_free_reserve_bytes": MINIMUM_FREE_RESERVE_BYTES,
            "planned_free_reserve_bytes": reserve,
        },
        "partition_table": partition_table,
        "system": {
            "hostname": spec["system"]["hostname"],
            "locale": spec["system"]["locale"],
            "timezone": spec["system"]["timezone"],
        },
        "network": {
            "mode": network["mode"],
            "address": network.get("address"),
            "prefix": network.get("prefix"),
            "gateway": network.get("gateway"),
            "dns": list(network.get("dns", [])),
            "manager": "systemd-networkd",
            "resolver": "systemd-resolved",
        },
        "administrator": {
            "username": administrator["username"],
            "authorized_key_sha256": [
                _sha256_bytes(key.encode()) for key in administrator["ssh_authorized_keys"]
            ],
            "local_console_password": (
                "precomputed-hash"
                if administrator.get("password_hash") is not None
                else "not-enrolled"
            ),
            "ssh_password_authentication": False,
            "sudo": "wheel-password-required",
        },
        "ssh": {
            "enabled": spec["ssh"]["enabled"],
            "root_login": False,
            "password_authentication": False,
        },
        "firewall": {
            "input_policy": "drop",
            "forward_policy": "drop",
            "output_policy": "accept",
            "allow_ssh": spec["firewall"]["ssh"],
        },
        "boot": {
            "mode": SUPPORTED_BOOT_MODE,
            "bootloader": SUPPORTED_BOOTLOADER,
            "kernel": SUPPORTED_KERNEL,
            "initramfs": "mkinitcpio",
            "root_identifier": (
                partition_table["root"]["mapper_device"]
                if "lvm" in partition_table
                else f"/dev/mapper/{partition_table['encryption']['mapper_name']}"
                if "encryption" in partition_table
                else f"PARTUUID={partition_table['root']['partition_uuid']}"
            ),
            **(
                {
                    "lvm_root": (
                        f"{partition_table['lvm']['volume_group']}/"
                        f"{partition_table['root']['name']}"
                    ),
                    "volume_group": partition_table["lvm"]["volume_group"],
                    "logical_volume": partition_table["root"]["name"],
                }
                if "lvm" in partition_table
                else {}
            ),
            **(
                {
                    "encrypted_root": True,
                    "luks_uuid": partition_table["encryption"]["luks_uuid"],
                    "mapper_name": partition_table["encryption"]["mapper_name"],
                }
                if "encryption" in partition_table
                else {}
            ),
            **(
                {"root_flags": _btrfs_root_flags(partition_table)}
                if _root_filesystem(partition_table) == "btrfs"
                else {}
            ),
        },
        "capacity_policy": {
            "absolute_minimum_bytes": 6 * GIB,
            "recommended_minimum_bytes": RECOMMENDED_MINIMUM_BYTES,
            "requested_minimum_bytes": spec["disk"]["minimum_capacity_bytes"],
        },
        "destructive_actions": (
            [
                *[
                    (
                        f"create partition {item['partition_number']} as {item['role']}"
                        if item["action"] == "create"
                        else f"format existing partition {item['partition_number']} as {item['filesystem']}"
                    )
                    for item in partition_table["partitions"]
                    if item.get("action") in {"create", "format"}
                ],
                "add KITPro boot files to the reused EFI System Partition"
                if partition_table["esp"].get("action") == "reuse"
                else "create and format the EFI System Partition as FAT32",
                *(
                    [
                        "create Btrfs subvolumes: "
                        + ", ".join(item["name"] for item in partition_table["subvolumes"])
                    ]
                    if _root_filesystem(partition_table) == "btrfs"
                    else []
                ),
                "deploy the pinned KITPro root filesystem",
            ]
            if partition_table.get("layout") == "preserve"
            else [
                "replace the target partition table with GPT",
                "create and format the EFI System Partition as FAT32",
                *(
                    [
                        "initialize the root partition as a LUKS2 container",
                        "open the encrypted root mapper using the runtime passphrase",
                        f"format the decrypted mapper as {_root_filesystem(partition_table)}",
                    ]
                    if "encryption" in partition_table
                    else [
                        f"create and format the root partition as {partition_table['root']['filesystem']}"
                    ]
                ),
                *(
                    [
                        "initialize the Linux LVM partition as one physical volume",
                        f"create volume group {partition_table['lvm']['volume_group']}",
                        "create and format the planned linear logical volumes",
                    ]
                    if "lvm" in partition_table
                    else []
                ),
                *(
                    [
                        "create Btrfs subvolumes: "
                        + ", ".join(item["name"] for item in partition_table["subvolumes"])
                    ]
                    if _root_filesystem(partition_table) == "btrfs"
                    else []
                ),
                *(
                    ["create and format a separate /home partition as ext4"]
                    if custom_storage and "home" in partition_table
                    else []
                ),
                *(
                    ["create and format a Linux swap partition"]
                    if custom_storage and "swap" in partition_table
                    else []
                ),
                *(
                    ["create and format a separate /var partition as ext4"]
                    if custom_storage and "var" in partition_table
                    else []
                ),
                *(
                    ["create and format a separate /srv partition as ext4"]
                    if custom_storage and "srv" in partition_table
                    else []
                ),
                "deploy the pinned KITPro root filesystem",
            ]
        ),
    }
    document["plan_sha256"] = _plan_hash(document)
    validate_plan_document(document)
    operations = _operations(document)
    unsigned_result = {
        "api_version": API_VERSION,
        "plan": document,
        "operations": list(operations),
    }
    result = PlanningResultV1(
        plan=document,
        operations=operations,
        result_sha256=_sha256_document(unsigned_result),
    )
    result.validate()
    return result


def _btrfs_root_flags(table: Mapping[str, Any]) -> str:
    options = ["subvol=@"]
    if table.get("compression") == "zstd":
        options.append("compress=zstd")
    return ",".join(options)


def _root_filesystem(table: Mapping[str, Any]) -> str:
    root = table["root"]
    return str(root.get("inner_filesystem", root["filesystem"]))


def _plan_hash(document: Mapping[str, Any]) -> str:
    value = dict(document)
    value.pop("plan_sha256", None)
    return _sha256_document(value)


def validate_plan_document(document: Mapping[str, Any]) -> None:
    """Validate the unchanged schema-v1 document consumed by KITPro execution."""
    required = {
        "schema_version",
        "installer_version",
        "install_spec_version",
        "install_spec_sha256",
        "plan_sha256",
        "target",
        "release",
        "repository_generation",
        "repository",
        "rootfs",
        "partition_table",
        "system",
        "network",
        "administrator",
        "ssh",
        "firewall",
        "boot",
        "capacity_policy",
        "destructive_actions",
    }
    missing = sorted(required - set(document))
    if missing:
        raise PlanningError(f"install plan misses fields: {missing}")
    if document["schema_version"] != 1 or document["install_spec_version"] != 1:
        raise PlanningError("unsupported install-plan or install-spec version")
    for field in ("install_spec_sha256", "plan_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document.get(field, ""))):
            raise PlanningError(f"invalid install plan hash: {field}")
    if document["plan_sha256"] != _plan_hash(document):
        raise PlanningError("install plan hash does not match its content")
    if document["partition_table"].get("type") != SUPPORTED_PARTITION_TABLE:
        raise PlanningError("install plan must use GPT")
    if document["boot"].get("mode") != SUPPORTED_BOOT_MODE:
        raise PlanningError("install plan must use UEFI")
    generation = document["repository_generation"]
    if generation != document["release"] + "-g" + generation.rsplit("-g", 1)[-1]:
        raise PlanningError("install plan release and generation disagree")


def _operation(
    order: int,
    operation_id: str,
    phase: str,
    action: str,
    purpose: str,
    mutates_target: bool,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "order": order,
        "id": operation_id,
        "phase": phase,
        "action": action,
        "purpose": purpose,
        "mutates_target": mutates_target,
        "arguments": dict(arguments),
    }


def _operations(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    target = plan["target"]
    esp = plan["partition_table"]["esp"]
    root = plan["partition_table"]["root"]
    network = plan["network"]
    ssh = plan["ssh"]
    encryption = plan["partition_table"].get("encryption")
    lvm = plan["partition_table"].get("lvm")
    root_filesystem = _root_filesystem(plan["partition_table"])
    if plan["partition_table"].get("layout") == "preserve":
        table = plan["partition_table"]
        storage_operations = []
        for partition in table["partitions"]:
            action = partition.get("action")
            if action == "create":
                storage_operations.append(
                    _operation(
                        0,
                        f"create-{partition['role']}-{partition['partition_number']}",
                        "storage",
                        f"create {partition['role']} partition in verified free space",
                        "Apply only the authorized incremental GPT addition",
                        True,
                        {
                            "partition_number": partition["partition_number"],
                            "start_bytes": partition["start_bytes"],
                            "size_bytes": partition["size_bytes"],
                            "type": partition["partition_type"],
                            "partition_uuid": partition["partition_uuid"],
                        },
                    )
                )
            if action in {"create", "format"}:
                storage_operations.append(
                    _operation(
                        0,
                        f"format-{partition['role']}-{partition['partition_number']}",
                        "filesystem",
                        f"format authorized {partition['role']} partition",
                        "Format only the partition explicitly designated by the plan",
                        True,
                        {
                            "partition_number": partition["partition_number"],
                            "filesystem": partition["filesystem"],
                            "mount_point": partition["mount_point"],
                        },
                    )
                )
        operations = [
            _operation(
                0,
                "verify-source",
                "preflight",
                "verify offline release inputs",
                "Trust only the explicitly verified generation",
                False,
                {"generation": plan["repository_generation"]},
            ),
            _operation(
                0,
                "revalidate-target",
                "preflight",
                "revalidate disk and exact existing partition identities",
                "Reject a stale plan before any storage mutation",
                False,
                {"target": target, "partitions": table["partitions"]},
            ),
            *storage_operations,
            _operation(
                0,
                "deploy-rootfs",
                "deployment",
                "deploy offline root filesystem",
                "Install the verified operating system inventory",
                True,
                {"source": plan["repository"]["source"]},
            ),
            _operation(
                0,
                "configure-system",
                "configuration",
                "configure installed system",
                "Apply identity, network, access, and mount policy",
                True,
                {"system": plan["system"], "network": network, "ssh": ssh},
            ),
            _operation(
                0,
                "install-boot",
                "boot",
                "add KITPro UEFI boot files and entry",
                "Preserve unrelated EFI files and boot entries",
                True,
                plan["boot"],
            ),
            _operation(
                0,
                "verify-preservation",
                "verification",
                "verify preserved partition identities and content evidence",
                "Prove unrelated partitions were not modified",
                False,
                {"preservation": table["preservation"]},
            ),
            _operation(
                0,
                "verify-result",
                "verification",
                "verify installed result",
                "Produce post-install evidence without changing policy",
                False,
                {"expected_plan_sha256": plan["plan_sha256"]},
            ),
        ]
        return tuple({**operation, "order": index} for index, operation in enumerate(operations, 1))
    encryption_operations = []
    if encryption is not None:
        encryption_operations = [
            _operation(
                0,
                "initialize-luks2",
                "filesystem",
                "initialize LUKS2 root container",
                "Protect root data with the approved LUKS2 policy",
                True,
                {key: value for key, value in encryption.items() if key != "enabled"},
            ),
            _operation(
                0,
                "open-cryptroot",
                "filesystem",
                "open encrypted root mapper",
                "Expose decrypted root storage for the committed installation",
                True,
                {"mapper_name": encryption["mapper_name"]},
            ),
        ]
    lvm_operations = []
    if lvm is not None:
        lvm_operations = [
            _operation(
                0,
                "initialize-lvm-pv",
                "storage",
                "initialize LVM physical volume",
                "Create the approved single-PV LVM boundary",
                True,
                {
                    "partition_role": lvm["physical_volume_role"],
                    **(
                        {"decrypted_mapper": f"/dev/mapper/{encryption['mapper_name']}"}
                        if encryption is not None
                        else {}
                    ),
                },
            ),
            _operation(
                0,
                "create-lvm-vg",
                "storage",
                "create LVM volume group",
                "Create the approved single volume group",
                True,
                {
                    "volume_group": lvm["volume_group"],
                    "extent_size_bytes": lvm["extent_size_bytes"],
                },
            ),
            _operation(
                0,
                "create-lvm-volumes",
                "storage",
                "create linear logical volumes",
                "Allocate only the authoritative extent counts",
                True,
                {"logical_volumes": lvm["logical_volumes"], "free_extents": lvm["free_extents"]},
            ),
        ]
    operations = (
        _operation(
            1,
            "verify-source",
            "preflight",
            "verify offline release inputs",
            "Trust only the explicitly verified generation",
            False,
            {
                "release": plan["release"],
                "generation": plan["repository_generation"],
                "manifest_sha256": plan["repository"]["generation_manifest_sha256"],
                "artifact_set_sha256": plan["repository"]["artifact_set_sha256"],
            },
        ),
        _operation(
            2,
            "revalidate-target",
            "preflight",
            "revalidate target identity",
            "Fail if the selected target changed or became mounted",
            False,
            {"target": target},
        ),
        _operation(
            3,
            "create-gpt",
            "storage",
            "replace the target partition table with GPT",
            "Establish the supported whole-disk layout",
            True,
            {"target": target["path"], "table": SUPPORTED_PARTITION_TABLE},
        ),
        _operation(
            4,
            "create-esp",
            "storage",
            "create EFI System Partition",
            "Provide UEFI boot storage",
            True,
            {
                "size_bytes": esp["size_bytes"],
                "type": esp["partition_type"],
                "partition_uuid": esp["partition_uuid"],
            },
        ),
        _operation(
            5,
            "format-esp",
            "filesystem",
            "format EFI System Partition",
            "Create the /efi filesystem",
            True,
            {"filesystem": esp["filesystem"], "mount_point": esp["mount_point"]},
        ),
        _operation(
            6,
            "create-lvm-partition" if lvm is not None else "create-root",
            "storage",
            "create Linux LVM partition" if lvm is not None else "create root partition",
            "Allocate the approved physical volume"
            if lvm is not None
            else "Allocate all remaining supported root space",
            True,
            (
                {
                    "size_policy": plan["partition_table"]["lvm-pv"]["size_policy"],
                    "planned_size_bytes": plan["partition_table"]["lvm-pv"]["planned_size_bytes"],
                    "type": plan["partition_table"]["lvm-pv"]["partition_type"],
                    "partition_uuid": plan["partition_table"]["lvm-pv"]["partition_uuid"],
                }
                if lvm is not None
                else {
                    "size_policy": root["size_policy"],
                    "minimum_size_bytes": root["minimum_size_bytes"],
                    "planned_size_bytes": root["planned_size_bytes"],
                    "type": root["partition_type"],
                    "partition_uuid": root["partition_uuid"],
                }
            ),
        ),
        *encryption_operations,
        *lvm_operations,
        _operation(
            7,
            "format-root",
            "filesystem",
            "format root logical volume"
            if lvm is not None
            else "format decrypted root mapper"
            if encryption is not None
            else "format root partition",
            "Create the supported root filesystem",
            True,
            {
                "filesystem": root_filesystem,
                "mount_point": root["mount_point"],
                **(
                    {
                        "subvolumes": plan["partition_table"]["subvolumes"],
                        "compression": plan["partition_table"]["compression"],
                    }
                    if root_filesystem == "btrfs"
                    else {}
                ),
            },
        ),
        _operation(
            8,
            "deploy-rootfs",
            "deployment",
            "deploy offline root filesystem",
            "Install the verified operating system inventory",
            True,
            {
                "source": plan["repository"]["source"],
                "profile_sha256": plan["rootfs"]["profile_sha256"],
                "package_count": plan["repository"]["package_count"],
            },
        ),
        _operation(
            9,
            "configure-system",
            "configuration",
            "configure system identity",
            "Apply hostname, locale, timezone, and administrator",
            True,
            {
                "system": plan["system"],
                "username": plan["administrator"]["username"],
                "local_console_password": plan["administrator"]["local_console_password"],
            },
        ),
        _operation(
            10,
            "configure-network",
            "configuration",
            "configure wired networking",
            "Apply the requested IPv4 policy to Name=en*",
            True,
            {"interface_match": NETWORK_INTERFACE_MATCH, **network},
        ),
        _operation(
            11,
            "configure-access",
            "configuration",
            "configure SSH and firewall",
            "Apply key-only remote access and default-deny firewall policy",
            True,
            {
                "ssh": ssh,
                "firewall": plan["firewall"],
                "authorized_key_sha256": plan["administrator"]["authorized_key_sha256"],
            },
        ),
        _operation(
            12,
            "install-boot",
            "boot",
            "install UEFI boot components",
            "Make the system bootable with the supported kernel",
            True,
            plan["boot"],
        ),
        _operation(
            13,
            "verify-result",
            "verification",
            "verify installed result",
            "Produce post-install evidence without changing policy",
            False,
            {
                "expected_release": plan["release"],
                "expected_generation": plan["repository_generation"],
                "expected_plan_sha256": plan["plan_sha256"],
            },
        ),
    )
    partition_table = plan["partition_table"]
    if "lvm" in partition_table:
        return tuple({**operation, "order": index} for index, operation in enumerate(operations, 1))
    if "partitions" not in partition_table:
        return operations
    additions: list[dict[str, Any]] = []
    details = {
        "home": ("home partition", "Create the separate /home filesystem"),
        "var": ("variable-data partition", "Create the separate /var filesystem"),
        "srv": ("server-data partition", "Create the separate /srv filesystem"),
        "swap": ("swap partition", "Create the configured paging space"),
    }
    optional_roles = [
        item["role"]
        for item in partition_table["partitions"]
        if item["role"] not in {"esp", "root"}
    ]
    for role in optional_roles:
        action_name, purpose = details[role]
        partition = partition_table.get(role)
        if partition is None:
            continue
        additions.extend(
            (
                _operation(
                    0,
                    f"create-{role}",
                    "storage",
                    f"create {action_name}",
                    purpose,
                    True,
                    {
                        "size_policy": partition["size_policy"],
                        "planned_size_bytes": partition["planned_size_bytes"],
                        "type": partition["partition_type"],
                        "partition_uuid": partition["partition_uuid"],
                    },
                ),
                _operation(
                    0,
                    f"format-{role}",
                    "filesystem",
                    f"format {action_name}",
                    purpose,
                    True,
                    {
                        "filesystem": partition["filesystem"],
                        "mount_point": partition["mount_point"],
                    },
                ),
            )
        )
    format_root_index = next(
        index for index, operation in enumerate(operations) if operation["id"] == "format-root"
    )
    combined = [
        *operations[:format_root_index],
        *additions,
        *operations[format_root_index:],
    ]
    return tuple({**operation, "order": index} for index, operation in enumerate(combined, 1))
