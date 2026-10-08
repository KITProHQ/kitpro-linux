"""Strict validation helpers for KITPro support-bundle format version 1."""

from __future__ import annotations

import re
from typing import Any

from tools.system_health import validate_health_report

try:
    from tools import kitpro_repo

    ValidationError = kitpro_repo.PipelineError
except ImportError:  # Installed support-inspection runtime has no repository tooling.
    class ValidationError(RuntimeError):
        """A controlled support-bundle validation failure."""


TOP_LEVEL_FIELDS = {
    "schema_version", "kind", "bundle_format_version", "bundle_id",
    "created_at", "mode", "redaction_profile", "product", "source",
    "limits", "health", "collectors", "files", "redaction",
    "secret_scan", "warnings", "errors", "collector_result", "archive",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_ID = re.compile(r"^support-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
SAFE_PATH = re.compile(r"^[a-z0-9][a-zA-Z0-9._/-]*$")


def _require_fields(document: dict[str, Any], fields: set[str], name: str) -> None:
    if set(document) != fields:
        raise ValidationError(f"support bundle {name} fields do not match version 1")


def _strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"support bundle {name} must contain strings")
    return value


def validate_manifest(document: dict[str, Any]) -> None:
    """Validate the strict shape and core semantics of a version 1 manifest."""
    _require_fields(document, TOP_LEVEL_FIELDS, "manifest")
    if document.get("schema_version") != 1 or document.get("kind") != "kitpro-support-bundle-manifest":
        raise ValidationError("unsupported support bundle manifest")
    if document.get("bundle_format_version") != 1 or not BUNDLE_ID.fullmatch(str(document.get("bundle_id", ""))):
        raise ValidationError("support bundle identity is invalid")
    if document.get("mode") not in {"live", "offline", "offline-rescue"}:
        raise ValidationError("support bundle mode is invalid")
    if document.get("redaction_profile") != "support-sanitized-v1":
        raise ValidationError("support bundle redaction profile is invalid")
    if document.get("collector_result") not in {"complete", "complete-with-warnings", "failed"}:
        raise ValidationError("support bundle result is invalid")
    _strings(document.get("warnings"), "warnings")
    _strings(document.get("errors"), "errors")

    product = document.get("product")
    if not isinstance(product, dict):
        raise ValidationError("support bundle product metadata is invalid")
    _require_fields(product, {"name", "release", "generation", "architecture", "kernel", "hostname_pseudonym"}, "product")
    if not re.fullmatch(r"HOST_[0-9]+", str(product.get("hostname_pseudonym", ""))):
        raise ValidationError("support bundle hostname pseudonym is invalid")

    source = document.get("source")
    if not isinstance(source, dict):
        raise ValidationError("support bundle source metadata is invalid")
    _require_fields(source, {"command", "version", "git_commit", "package_build"}, "source")
    if source.get("command") != "kitpro-support-bundle" or source.get("version") not in {"0.1", "0.2", "0.3", "0.4"}:
        raise ValidationError("support bundle source identity is invalid")

    limits = document.get("limits")
    if not isinstance(limits, dict):
        raise ValidationError("support bundle limits are invalid")
    _require_fields(limits, {"individual_file_bytes", "journal_file_bytes", "staging_bytes", "archive_bytes", "collector_timeout_seconds"}, "limits")
    if not all(isinstance(value, int) and value > 0 for value in limits.values()):
        raise ValidationError("support bundle limits must be positive integers")

    health = document.get("health")
    if not isinstance(health, dict):
        raise ValidationError("support bundle health reference is invalid")
    _require_fields(health, {"path", "sha256", "overall_status"}, "health")
    if health.get("path") != "health/system-health.json" or not SHA256.fullmatch(str(health.get("sha256", ""))):
        raise ValidationError("support bundle health integrity is invalid")
    if health.get("overall_status") not in {"healthy", "warning", "error", "unknown"}:
        raise ValidationError("support bundle health status is invalid")

    collectors = document.get("collectors")
    if not isinstance(collectors, list):
        raise ValidationError("support bundle collectors are invalid")
    collector_fields = {"id", "critical", "status", "exit_code", "timed_out", "output_files", "stderr_file", "truncated", "original_bytes", "stored_bytes"}
    for collector in collectors:
        if not isinstance(collector, dict):
            raise ValidationError("support bundle collector is invalid")
        _require_fields(collector, collector_fields, "collector")
        if collector.get("status") not in {"collected", "unavailable", "failed"}:
            raise ValidationError("support bundle collector status is invalid")
        _strings(collector.get("output_files"), "collector output_files")

    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise ValidationError("support bundle file inventory is empty")
    file_fields = {"path", "sha256", "size_bytes", "truncated", "redaction_status"}
    paths: list[str] = []
    for item in files:
        if not isinstance(item, dict):
            raise ValidationError("support bundle file entry is invalid")
        _require_fields(item, file_fields, "file")
        path = item.get("path")
        if not isinstance(path, str) or not safe_member_path(path):
            raise ValidationError("support bundle file path is unsafe")
        if not SHA256.fullmatch(str(item.get("sha256", ""))):
            raise ValidationError("support bundle file hash is invalid")
        if not isinstance(item.get("size_bytes"), int) or item["size_bytes"] < 0:
            raise ValidationError("support bundle file size is invalid")
        if item.get("redaction_status") != "sanitized":
            raise ValidationError("support bundle file is not sanitized")
        paths.append(path)
    if paths != canonical_member_order(paths):
        raise ValidationError("support bundle file inventory is not canonical")

    redaction = document.get("redaction")
    if not isinstance(redaction, dict):
        raise ValidationError("support bundle redaction metadata is invalid")
    _require_fields(redaction, {"report", "status", "total_replacements", "categories"}, "redaction")
    if redaction.get("report") != "redaction/report.json" or redaction.get("status") != "sanitized":
        raise ValidationError("support bundle redaction did not complete")
    _strings(redaction.get("categories"), "redaction categories")

    scan = document.get("secret_scan")
    if scan != {"report": "redaction/secret-scan.json", "status": "passed", "finding_count": 0}:
        raise ValidationError("support bundle secret scan did not pass")
    archive = document.get("archive")
    if not isinstance(archive, dict):
        raise ValidationError("support bundle archive metadata is invalid")
    _require_fields(archive, {"format", "filename", "sha256_recorded_externally"}, "archive")
    if archive.get("format") != "tar.zst" or archive.get("sha256_recorded_externally") is not True:
        raise ValidationError("support bundle archive format is invalid")


def safe_member_path(path: str) -> bool:
    """Return true only for normalized relative regular-file paths."""
    return bool(
        SAFE_PATH.fullmatch(path)
        and not path.startswith("/")
        and path not in {".", ".."}
        and "//" not in path
        and all(part not in {"", ".", ".."} for part in path.split("/"))
    )


def validate_health_payload(document: dict[str, Any]) -> None:
    """Keep the bundle health payload on the Phase 8.3 contract."""
    validate_health_report(document)


def canonical_member_order(paths: list[str]) -> list[str]:
    """Order unique normalized ASCII member names by bytes, never locale.

    Names use '/' separators and must already satisfy safe_member_path; no
    normalization, natural sorting, or case folding is performed.
    """
    if any(not safe_member_path(path) for path in paths):
        raise ValidationError("support bundle member name is unsafe")
    if len(paths) != len(set(paths)):
        raise ValidationError("support bundle member names are duplicated")
    return sorted(paths, key=lambda path: path.encode("ascii"))
