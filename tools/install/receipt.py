"""Build the public installation receipt written into an installed system."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tools import kitpro_repo


SOURCE_FIELDS = {
    "kind", "media_version", "source_git_commit", "profile_sha256",
    "build_configuration_sha256", "product_name", "product_version",
    "release_status", "repository_release", "repository_generation",
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
    for field in ("media_version", "source_git_commit", "profile_sha256", "build_configuration_sha256"):
        value = document.get(field)
        if not isinstance(value, str) or not value:
            raise kitpro_repo.PipelineError(f"installation source metadata misses {field}")
    for field in (
        "product_name", "product_version", "release_status",
        "repository_release", "repository_generation", "media_build_identity",
    ):
        value = document.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise kitpro_repo.PipelineError(
                f"installation source metadata has invalid {field}"
            )
    if not re.fullmatch(r"[0-9a-f]{40}", document["source_git_commit"]):
        raise kitpro_repo.PipelineError("installation source metadata has an invalid Git commit")
    for field in ("profile_sha256", "build_configuration_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", document[field]):
            raise kitpro_repo.PipelineError(f"installation source metadata has an invalid {field}")
    if document["kind"] == "production-iso":
        release = document.get("repository_release", "")
        status = document.get("release_status", "")
        expected_media_version = release if status == "Stable" else f"{release}-{status.lower()}"
        if (document.get("product_name") != "KITPro Linux Server"
                or not re.fullmatch(r"[0-9]+\.[0-9]+", release)
                or document.get("product_version") != release
                or not re.fullmatch(re.escape(release) + r"-g[0-9]{4}", document.get("repository_generation", ""))
                or not re.fullmatch(r"RC[1-9][0-9]*|Stable", document.get("release_status", ""))
                or document.get("media_build_identity") != document["media_version"]
                or document["media_version"] != expected_media_version
                or not re.fullmatch(re.escape(release) + r"(?:-rc[1-9][0-9]*)?", document["media_version"])):
            raise kitpro_repo.PipelineError("production media identity is invalid")
    return document


def build_receipt(
    plan: dict[str, Any], installed_at: str, source: dict[str, Any]
) -> dict[str, Any]:
    receipt = {
        "schema_version": 1,
        "installer_version": plan["installer_version"],
        "installation_source": source,
        "installed_at": installed_at,
        "release": plan["release"],
        "repository_generation": plan["repository_generation"],
        "install_spec_sha256": plan["install_spec_sha256"],
        "install_plan_sha256": plan["plan_sha256"],
        "generation_manifest_sha256": plan["repository"]["generation_manifest_sha256"],
        "partition_table": "gpt",
        "partitions": {
            "esp_partuuid": plan["partition_table"]["esp"]["partition_uuid"],
            "root_partuuid": plan["partition_table"]["root"]["partition_uuid"],
        },
    }
    validate_receipt(receipt)
    return receipt


def validate_receipt(document: dict[str, Any]) -> None:
    required = {
        "schema_version", "installer_version", "installation_source", "installed_at",
        "release", "repository_generation", "install_spec_sha256", "install_plan_sha256",
        "generation_manifest_sha256", "partition_table", "partitions",
    }
    if set(document) != required:
        raise kitpro_repo.PipelineError("installation receipt fields do not match schema version 1")
    if document["schema_version"] != 1 or document["partition_table"] != "gpt":
        raise kitpro_repo.PipelineError("installation receipt has an unsupported schema or layout")
    for field in ("install_spec_sha256", "install_plan_sha256", "generation_manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document[field])):
            raise kitpro_repo.PipelineError(f"installation receipt has an invalid hash: {field}")
    partitions = document["partitions"]
    if set(partitions) != {"esp_partuuid", "root_partuuid"}:
        raise kitpro_repo.PipelineError("installation receipt has invalid partition identifiers")
    for value in partitions.values():
        if not re.fullmatch(r"[0-9a-f-]{36}", str(value)):
            raise kitpro_repo.PipelineError("installation receipt has an invalid PARTUUID")
