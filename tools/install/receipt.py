"""Build the public installation receipt written into an installed system."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools import kitpro_repo

SOURCE_FIELDS = {
    "kind",
    "media_version",
    "source_git_commit",
    "profile_sha256",
    "build_configuration_sha256",
    "product_name",
    "product_version",
    "release_status",
    "repository_release",
    "repository_generation",
    "media_build_identity",
}


def load_source_metadata(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"kind": "development-environment"}
    document = kitpro_repo.load_json(path)
    if not isinstance(document, dict):
        raise kitpro_repo.PipelineError("installation source metadata must be an object")
    unknown = sorted(set(document) - SOURCE_FIELDS)
    if unknown:
        raise kitpro_repo.PipelineError(
            f"installation source metadata contains unsupported fields: {unknown}"
        )
    if document.get("kind") not in {"developer-iso", "production-iso"}:
        raise kitpro_repo.PipelineError("installation source metadata has an unsupported kind")
    for field in (
        "media_version",
        "source_git_commit",
        "profile_sha256",
        "build_configuration_sha256",
    ):
        value = document.get(field)
        if not isinstance(value, str) or not value:
            raise kitpro_repo.PipelineError(f"installation source metadata misses {field}")
    for field in (
        "product_name",
        "product_version",
        "release_status",
        "repository_release",
        "repository_generation",
        "media_build_identity",
    ):
        value = document.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise kitpro_repo.PipelineError(f"installation source metadata has invalid {field}")
    if not re.fullmatch(r"[0-9a-f]{40}", document["source_git_commit"]):
        raise kitpro_repo.PipelineError("installation source metadata has an invalid Git commit")
    for field in ("profile_sha256", "build_configuration_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", document[field]):
            raise kitpro_repo.PipelineError(f"installation source metadata has an invalid {field}")
    if document["kind"] == "production-iso":
        release = document.get("repository_release", "")
        status = document.get("release_status", "")
        expected_media_version = release if status == "Stable" else f"{release}-{status.lower()}"
        if (
            document.get("product_name") != "KITPro Linux Server"
            or not re.fullmatch(r"[0-9]+\.[0-9]+", release)
            or document.get("product_version") != release
            or not re.fullmatch(
                re.escape(release) + r"-g[0-9]{4}", document.get("repository_generation", "")
            )
            or not re.fullmatch(r"RC[1-9][0-9]*|Stable", document.get("release_status", ""))
            or document.get("media_build_identity") != document["media_version"]
            or document["media_version"] != expected_media_version
            or not re.fullmatch(
                re.escape(release) + r"(?:-rc[1-9][0-9]*)?", document["media_version"]
            )
        ):
            raise kitpro_repo.PipelineError("production media identity is invalid")
    return document


def build_receipt(
    plan: dict[str, Any], installed_at: str, source: dict[str, Any]
) -> dict[str, Any]:
    lvm = plan["partition_table"].get("lvm")
    reused_esp = (
        plan["partition_table"].get("layout") == "preserve"
        and plan["partition_table"]["esp"].get("action") == "reuse"
    )
    partitions = {"esp_partuuid": plan["partition_table"]["esp"]["partition_uuid"]}
    if lvm:
        partitions["lvm_pv_partuuid"] = plan["partition_table"]["lvm-pv"]["partition_uuid"]
    else:
        partitions["root_partuuid"] = plan["partition_table"]["root"]["partition_uuid"]
    for role in ("home", "var", "srv", "swap"):
        if not lvm and role in plan["partition_table"]:
            partitions[f"{role}_partuuid"] = plan["partition_table"][role]["partition_uuid"]
    receipt = {
        "schema_version": (
            5
            if reused_esp
            else 4
            if lvm and "encryption" in plan["partition_table"]
            else 3
            if lvm
            else 2
            if "encryption" in plan["partition_table"]
            else 1
        ),
        "installer_version": plan["installer_version"],
        "installation_source": source,
        "installed_at": installed_at,
        "release": plan["release"],
        "repository_generation": plan["repository_generation"],
        "install_spec_sha256": plan["install_spec_sha256"],
        "install_plan_sha256": plan["plan_sha256"],
        "generation_manifest_sha256": plan["repository"]["generation_manifest_sha256"],
        "partition_table": "gpt",
        "partitions": partitions,
    }
    if reused_esp:
        receipt["preservation"] = {
            "mode": "preserve",
            "esp_action": "reuse",
            "esp_partuuid": partitions["esp_partuuid"],
            "bootloader_path": "/EFI/KITPRO/kitpro-bootx64.efi",
        }
    if "encryption" in plan["partition_table"]:
        encryption = plan["partition_table"]["encryption"]
        receipt["encryption"] = {
            "enabled": True,
            "type": "luks2",
            "luks_version": encryption["luks_version"],
            "encrypted_partition_partuuid": encryption["partition_uuid"],
            "luks_uuid": encryption["luks_uuid"],
            "mapper_name": encryption["mapper_name"],
            "root_filesystem": plan["partition_table"]["filesystem"],
            "boot_activation": "systemd-initramfs",
        }
    if lvm:
        receipt["lvm"] = {
            "enabled": True,
            "physical_volume_partuuid": partitions["lvm_pv_partuuid"],
            "volume_group": lvm["volume_group"],
            "extent_size_bytes": lvm["extent_size_bytes"],
            "free_extents": lvm["free_extents"],
            "root_device": plan["partition_table"]["root"]["mapper_device"],
            "logical_volumes": [
                {
                    key: volume[key]
                    for key in ("name", "role", "filesystem", "mount_point", "size_bytes")
                }
                for volume in lvm["logical_volumes"]
            ],
        }
    validate_receipt(receipt)
    return receipt


def validate_receipt(document: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "installer_version",
        "installation_source",
        "installed_at",
        "release",
        "repository_generation",
        "install_spec_sha256",
        "install_plan_sha256",
        "generation_manifest_sha256",
        "partition_table",
        "partitions",
    }
    schema = document.get("schema_version")
    expected = required | (
        {"preservation"}
        if schema == 5
        else {"encryption", "lvm"}
        if schema == 4
        else {"encryption"}
        if schema == 2
        else {"lvm"}
        if schema == 3
        else set()
    )
    if set(document) != expected:
        raise kitpro_repo.PipelineError("installation receipt fields do not match its schema")
    if schema not in {1, 2, 3, 4, 5} or document["partition_table"] != "gpt":
        raise kitpro_repo.PipelineError("installation receipt has an unsupported schema or layout")
    for field in ("install_spec_sha256", "install_plan_sha256", "generation_manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document[field])):
            raise kitpro_repo.PipelineError(f"installation receipt has an invalid hash: {field}")
    partitions = document["partitions"]
    required_partitions = (
        {"esp_partuuid", "lvm_pv_partuuid"}
        if schema in {3, 4}
        else {"esp_partuuid", "root_partuuid"}
    )
    allowed_partitions = required_partitions | {
        "home_partuuid",
        "var_partuuid",
        "srv_partuuid",
        "swap_partuuid",
        "lvm_pv_partuuid",
    }
    if not required_partitions <= set(partitions) or set(partitions) - allowed_partitions:
        raise kitpro_repo.PipelineError("installation receipt has invalid partition identifiers")
    for value in partitions.values():
        if not re.fullmatch(r"[0-9a-f-]{36}", str(value)):
            raise kitpro_repo.PipelineError("installation receipt has an invalid PARTUUID")
    if schema == 5:
        preservation = document["preservation"]
        if (
            not isinstance(preservation, dict)
            or set(preservation)
            != {"mode", "esp_action", "esp_partuuid", "bootloader_path"}
            or preservation.get("mode") != "preserve"
            or preservation.get("esp_action") != "reuse"
            or preservation.get("esp_partuuid") != partitions["esp_partuuid"]
            or preservation.get("bootloader_path")
            != "/EFI/KITPRO/kitpro-bootx64.efi"
        ):
            raise kitpro_repo.PipelineError("installation receipt has invalid EFI reuse evidence")
    if schema in {2, 4}:
        encryption = document["encryption"]
        required_encryption = {
            "enabled",
            "type",
            "luks_version",
            "encrypted_partition_partuuid",
            "luks_uuid",
            "mapper_name",
            "root_filesystem",
            "boot_activation",
        }
        if (
            not isinstance(encryption, dict)
            or set(encryption) != required_encryption
            or encryption.get("enabled") is not True
            or encryption.get("type") != "luks2"
            or encryption.get("luks_version") != 2
            or encryption.get("mapper_name") != ("cryptlvm" if schema == 4 else "cryptroot")
            or encryption.get("root_filesystem") not in {"ext4", "btrfs"}
            or encryption.get("boot_activation") != "systemd-initramfs"
            or not re.fullmatch(r"[0-9a-f-]{36}", str(encryption.get("luks_uuid", "")))
            or encryption.get("encrypted_partition_partuuid")
            != partitions["lvm_pv_partuuid" if schema == 4 else "root_partuuid"]
        ):
            raise kitpro_repo.PipelineError("installation receipt has invalid encryption evidence")
    if schema in {3, 4}:
        lvm = document["lvm"]
        required_lvm = {
            "enabled",
            "physical_volume_partuuid",
            "volume_group",
            "extent_size_bytes",
            "free_extents",
            "root_device",
            "logical_volumes",
        }
        if (
            not isinstance(lvm, dict)
            or set(lvm) != required_lvm
            or lvm.get("enabled") is not True
            or lvm.get("physical_volume_partuuid") != partitions["lvm_pv_partuuid"]
            or not re.fullmatch(r"[A-Za-z0-9_]{1,63}", str(lvm.get("volume_group", "")))
            or not isinstance(lvm.get("extent_size_bytes"), int)
            or not isinstance(lvm.get("free_extents"), int)
            or not str(lvm.get("root_device", "")).startswith("/dev/mapper/")
            or not isinstance(lvm.get("logical_volumes"), list)
            or not any(item.get("role") == "root" for item in lvm["logical_volumes"])
        ):
            raise kitpro_repo.PipelineError("installation receipt has invalid LVM evidence")
