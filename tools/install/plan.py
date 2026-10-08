"""Deterministic installation-plan generation and validation."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from tools import kitpro_repo
from tools.install import INSTALLER_VERSION
from tools.install.disk import DiskState, discover_disk
from tools.install.model import (
    ESP_SIZE_BYTES,
    MINIMUM_FREE_RESERVE_BYTES,
    RECOMMENDED_MINIMUM_BYTES,
    InstallSpec,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT / "repo"
KEY_ROOT = PROJECT_ROOT / ".state/dev-keys"
ROOTFS_PROFILE = PROJECT_ROOT / "config/install-rootfs-profile.json"
PLAN_NAMESPACE = uuid.UUID("1b28362f-69f8-4eb1-984c-c35cd5578257")
ROOTFS_ESTIMATE_BYTES = 3 * 1024**3
PARTITION_OVERHEAD_BYTES = 2 * 1024**2


def _plan_hash(document: dict[str, Any]) -> str:
    value = dict(document)
    value.pop("plan_sha256", None)
    return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(value))


def _generation(spec: InstallSpec) -> tuple[Path, dict[str, Any]]:
    if spec.release.name == "1.0":
        from tools.install import production
        return production.verify(spec.release.generation, REPO_ROOT)
    root = REPO_ROOT / "stable" / spec.release.name / spec.release.generation
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise kitpro_repo.PipelineError(
            f"pinned Stable generation is unavailable: {spec.release.generation}"
        )
    manifest = kitpro_repo.load_json(manifest_path)
    kitpro_repo.validate_manifest(manifest)
    if manifest["release"] != spec.release.name or manifest["generation_id"] != spec.release.generation:
        raise kitpro_repo.PipelineError("pinned Stable generation metadata does not match the spec")
    kitpro_repo.verify_manifest_artifacts(manifest, REPO_ROOT, root, KEY_ROOT)
    return root, manifest


def build_plan(spec: InstallSpec) -> dict[str, Any]:
    disk = discover_disk(
        Path(spec.disk.device), spec.disk.target_type, spec.disk.minimum_capacity_bytes
    )
    generation_root, manifest = _generation(spec)
    generation_manifest_sha256 = kitpro_repo.sha256_file(generation_root / "manifest.json")
    production = spec.release.name == "1.0"
    package_count = (manifest["package_count"] if production else
                     sum(len(repository["packages"]) for repository in manifest["repositories"]))
    profile = kitpro_repo.load_json(ROOTFS_PROFILE)
    if profile["release"] != spec.release.name or profile["generation"] != spec.release.generation:
        raise kitpro_repo.PipelineError("rootfs profile does not match the pinned Stable generation")
    if production and sorted(profile["explicit_packages"]) != sorted(
        p["name"] for p in manifest["packages"] if p["explicit"]
    ):
        raise kitpro_repo.PipelineError("production profile differs from frozen explicit inventory")
    usable_root_bytes = disk.size_bytes - ESP_SIZE_BYTES - PARTITION_OVERHEAD_BYTES
    reserve_bytes = usable_root_bytes - ROOTFS_ESTIMATE_BYTES
    if reserve_bytes < MINIMUM_FREE_RESERVE_BYTES:
        raise kitpro_repo.PipelineError(
            f"planned root filesystem reserve is too small: {reserve_bytes} bytes"
        )
    seed_material = kitpro_repo.canonical_json_bytes(
        {
            "spec_sha256": spec.sha256(),
            "target": disk.to_dict(),
            "generation_manifest_sha256": generation_manifest_sha256,
        }
    ).decode()
    esp_uuid = str(uuid.uuid5(PLAN_NAMESPACE, seed_material + ":esp"))
    root_uuid = str(uuid.uuid5(PLAN_NAMESPACE, seed_material + ":root"))
    key_hashes = [
        kitpro_repo.sha256_bytes(key.encode()) for key in spec.administrator.ssh_authorized_keys
    ]
    document: dict[str, Any] = {
        "schema_version": 1,
        "installer_version": INSTALLER_VERSION,
        "install_spec_version": spec.version,
        "install_spec_sha256": spec.sha256(),
        "target": disk.to_dict(),
        "release": spec.release.name,
        "repository_generation": spec.release.generation,
        "repository": {
            "generation_manifest_sha256": generation_manifest_sha256,
            "artifact_set_sha256": (manifest["artifact_set_sha256"] if production
                                    else kitpro_repo.manifest_artifact_hash(manifest)),
            "package_count": package_count,
            "source": str(generation_root.relative_to(PROJECT_ROOT)),
        },
        "rootfs": {
            "profile_sha256": kitpro_repo.sha256_file(ROOTFS_PROFILE),
            "estimated_size_bytes": ROOTFS_ESTIMATE_BYTES,
            "minimum_free_reserve_bytes": MINIMUM_FREE_RESERVE_BYTES,
            "planned_free_reserve_bytes": reserve_bytes,
        },
        "partition_table": {
            "type": "gpt",
            "esp": {
                "size_bytes": ESP_SIZE_BYTES,
                "partition_type": "esp",
                "partition_uuid": esp_uuid,
                "filesystem": "vfat",
                "mount_point": "/efi",
            },
            "root": {
                "size_policy": "remaining",
                "minimum_size_bytes": 5 * 1024**3,
                "planned_size_bytes": usable_root_bytes,
                "partition_type": "root-x86-64",
                "partition_uuid": root_uuid,
                "filesystem": "ext4",
                "mount_point": "/",
            },
        },
        "system": {
            "hostname": spec.system.hostname,
            "locale": spec.system.locale,
            "timezone": spec.system.timezone,
        },
        "network": {
            "mode": spec.network.mode,
            "address": spec.network.address,
            "prefix": spec.network.prefix,
            "gateway": spec.network.gateway,
            "dns": list(spec.network.dns),
            "manager": "systemd-networkd",
            "resolver": "systemd-resolved",
        },
        "administrator": {
            "username": spec.administrator.username,
            "authorized_key_sha256": key_hashes,
            "local_console_password": (
                "precomputed-hash"
                if spec.administrator.password_hash is not None
                else "not-enrolled"
            ),
            "ssh_password_authentication": False,
            "sudo": "wheel-password-required",
        },
        "ssh": {
            "enabled": spec.ssh.enabled,
            "root_login": False,
            "password_authentication": False,
        },
        "firewall": {
            "input_policy": "drop",
            "forward_policy": "drop",
            "output_policy": "accept",
            "allow_ssh": spec.firewall.ssh,
        },
        "boot": {
            "mode": "uefi",
            "bootloader": "systemd-boot",
            "kernel": "linux-lts",
            "initramfs": "mkinitcpio",
            "root_identifier": f"PARTUUID={root_uuid}",
        },
        "capacity_policy": {
            "absolute_minimum_bytes": 6 * 1024**3,
            "recommended_minimum_bytes": RECOMMENDED_MINIMUM_BYTES,
            "requested_minimum_bytes": spec.disk.minimum_capacity_bytes,
        },
        "destructive_actions": [
            "replace the target partition table with GPT",
            "create and format the EFI System Partition as FAT32",
            "create and format the root partition as ext4",
            "deploy the pinned KITPro root filesystem",
        ],
    }
    document["plan_sha256"] = _plan_hash(document)
    validate_plan(document)
    return document


def validate_plan(document: dict[str, Any]) -> None:
    required = {
        "schema_version", "installer_version", "install_spec_version", "install_spec_sha256",
        "plan_sha256", "target", "release", "repository_generation", "repository", "rootfs",
        "partition_table", "system", "network", "administrator", "ssh", "firewall", "boot",
        "capacity_policy", "destructive_actions",
    }
    missing = sorted(required - set(document))
    if missing:
        raise kitpro_repo.PipelineError(f"install plan misses fields: {missing}")
    if document["schema_version"] != 1 or document["install_spec_version"] != 1:
        raise kitpro_repo.PipelineError("unsupported install-plan or install-spec version")
    for field in ("install_spec_sha256", "plan_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document.get(field, ""))):
            raise kitpro_repo.PipelineError(f"invalid install plan hash: {field}")
    if document["plan_sha256"] != _plan_hash(document):
        raise kitpro_repo.PipelineError("install plan hash does not match its content")
    if document["partition_table"].get("type") != "gpt":
        raise kitpro_repo.PipelineError("install plan must use GPT")
    if document["boot"].get("mode") != "uefi":
        raise kitpro_repo.PipelineError("install plan must use UEFI")
    if document["repository_generation"] != document["release"] + "-g" + document["repository_generation"].rsplit("-g", 1)[-1]:
        raise kitpro_repo.PipelineError("install plan release and generation disagree")


def load_plan(path: Path) -> dict[str, Any]:
    document = kitpro_repo.load_json(path)
    if not isinstance(document, dict):
        raise kitpro_repo.PipelineError("install plan must be a JSON object")
    validate_plan(document)
    return document


def plan_disk_state(document: dict[str, Any]) -> DiskState:
    value = document["target"]
    return DiskState(
        path=value["path"],
        target_type=value["target_type"],
        size_bytes=value["size_bytes"],
        identity=value["identity"],
        mounted_paths=tuple(value["mounted_paths"]),
        signatures=tuple(value["signatures"]),
        partition_table=value["partition_table"],
        marker_sha256=value.get("marker_sha256"),
    )
