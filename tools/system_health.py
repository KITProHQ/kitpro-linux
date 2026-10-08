"""Validation helpers for the versioned KITPro system-health document."""

from __future__ import annotations

from typing import Any

try:
    from tools import kitpro_repo

    ValidationError = kitpro_repo.PipelineError
except ImportError:  # Installed support-inspection runtime has no repository tooling.
    class ValidationError(RuntimeError):
        """A controlled health-document validation failure."""


TOP_LEVEL_FIELDS = {
    "schema_version", "kind", "timestamp", "mode", "system", "kernel",
    "boot", "systemd", "networking", "dns", "firewall", "ssh",
    "repository", "storage", "history", "redaction", "overall_status",
    "warnings", "errors",
}


def _object(document: dict[str, Any], field: str, required: set[str]) -> dict[str, Any]:
    value = document.get(field)
    if not isinstance(value, dict) or set(value) != required:
        raise ValidationError(f"system health {field} fields do not match schema version 1")
    return value


def validate_health_report(document: dict[str, Any]) -> None:
    """Validate the strict shape and semantic discriminators of schema version 1."""
    if set(document) != TOP_LEVEL_FIELDS:
        raise ValidationError("system health fields do not match schema version 1")
    if document.get("schema_version") != 1 or document.get("kind") != "kitpro-system-health":
        raise ValidationError("unsupported system health schema or kind")
    if document.get("mode") not in {"live", "offline"}:
        raise ValidationError("system health mode is invalid")
    if document.get("overall_status") not in {"healthy", "warning", "error", "unknown"}:
        raise ValidationError("system health overall status is invalid")
    for field in ("warnings", "errors"):
        if not isinstance(document.get(field), list) or not all(
            isinstance(item, str) for item in document[field]
        ):
            raise ValidationError(f"system health {field} must be strings")
    _object(
        document, "system",
        {"product", "release", "generation", "hostname", "architecture", "uptime_seconds"},
    )
    kernel = _object(
        document, "kernel",
        {
            "schema_version", "kind", "timestamp", "running_kernel", "boot_mode",
            "expected_running_kernel_match", "current", "candidate",
            "previous_known_good", "fallback", "reboot_required", "transition_stage",
            "transition_id", "latest_transition_receipt", "retention_preflight",
            "metadata_consistency", "overall_status", "warnings", "errors",
        },
    )
    if kernel.get("schema_version") != 1 or kernel.get("kind") != "kitpro-kernel-status":
        raise ValidationError("embedded kernel status has an unsupported schema")
    if kernel.get("overall_status") not in {"healthy", "warning", "error"}:
        raise ValidationError("embedded kernel status severity is invalid")
    _object(
        document, "boot",
        {"firmware", "esp_present", "esp_mounted", "systemd_boot_valid", "default_entry", "current_entry_valid", "fallback_entry_valid", "kernel_image_valid", "initramfs_valid"},
    )
    systemd = _object(
        document, "systemd",
        {"failed_unit_count", "failed_units", "critical_failed_units", "services"},
    )
    if not isinstance(systemd["failed_unit_count"], int) or systemd["failed_unit_count"] < 0:
        raise ValidationError("system health failed-unit count is invalid")
    _object(
        document, "networking",
        {"configuration_present", "configuration_files", "active_interfaces", "global_address_present", "default_route_present", "networkd_state"},
    )
    _object(document, "dns", {"resolved_state", "resolv_conf_valid", "validation"})
    _object(document, "firewall", {"service_state", "configuration_valid", "ruleset_available", "baseline_policy_valid"})
    _object(document, "ssh", {"enabled", "service_state", "configuration_valid", "syntax", "listening", "root_login", "password_authentication"})
    repository = _object(
        document, "repository",
        {"enabled_repositories", "generation", "kitpro_only", "signature_enforcement", "arch_repositories_present", "package_database_readable", "installed_package_count", "release_package_present", "kernel_package_present"},
    )
    if not isinstance(repository["installed_package_count"], int) or repository["installed_package_count"] < 0:
        raise ValidationError("system health package count is invalid")
    storage = _object(document, "storage", {"root", "esp", "kernel_retention"})
    for volume in ("root", "esp"):
        value = storage.get(volume)
        if not isinstance(value, dict) or set(value) != {
            "filesystem", "total_bytes", "free_bytes", "low_space"
        }:
            raise ValidationError(f"system health {volume} storage is invalid")
    _object(document, "history", {"install_receipt", "kernel_transition", "recovery"})
    redaction = _object(document, "redaction", {"profile", "sensitive_values_included"})
    if redaction != {"profile": "support-safe-v1", "sensitive_values_included": False}:
        raise ValidationError("system health redaction declaration is invalid")


def subsystem_summary(document: dict[str, Any]) -> dict[str, str]:
    """Summarize a validated health report without inventing a second health model."""
    validate_health_report(document)
    offline = document["mode"] == "offline"
    boot = document["boot"]
    repository = document["repository"]
    storage = document["storage"]
    networking = document["networking"]
    firewall = document["firewall"]
    ssh = document["ssh"]
    systemd = document["systemd"]

    boot_status = "healthy" if all(
        (
            boot["systemd_boot_valid"], boot["current_entry_valid"],
            boot["kernel_image_valid"], boot["initramfs_valid"],
        )
    ) else "error"
    repository_status = "healthy" if all(
        (
            repository["kitpro_only"], repository["signature_enforcement"],
            not repository["arch_repositories_present"],
            repository["package_database_readable"],
            repository["release_package_present"], repository["kernel_package_present"],
        )
    ) else "error"
    storage_status = "warning" if (
        storage["root"]["low_space"] or storage["esp"]["low_space"]
        or storage["kernel_retention"] not in {"ready", "not-applicable"}
    ) else "healthy"
    if offline:
        systemd_status = networking_status = "unavailable"
    else:
        systemd_status = "error" if systemd["critical_failed_units"] else (
            "warning" if systemd["failed_unit_count"] else "healthy"
        )
        networking_status = "healthy" if all(
            (
                networking["configuration_present"], networking["global_address_present"],
                networking["default_route_present"], networking["networkd_state"] == "active",
            )
        ) else "warning"
    dns_status = {"healthy": "healthy", "degraded": "warning", "unavailable": "unavailable"}[
        document["dns"]["validation"]
    ]
    if not firewall["configuration_valid"] or not firewall["baseline_policy_valid"]:
        firewall_status = "error"
    elif offline:
        firewall_status = "unavailable"
    else:
        firewall_status = "healthy" if (
            firewall["service_state"] in {"active", "exited", "inactive-success"}
            and firewall["ruleset_available"] is True
        ) else "warning"
    if (
        not ssh["configuration_valid"]
        or ssh["root_login"] not in {"no", "disabled"}
        or ssh["password_authentication"] not in {"no", "disabled"}
    ):
        ssh_status = "error"
    elif not ssh["enabled"]:
        ssh_status = "healthy"
    elif offline:
        ssh_status = "unavailable"
    else:
        ssh_status = "healthy" if ssh["service_state"] == "active" and ssh["listening"] is True else "warning"

    summary = {
        "kernel": document["kernel"]["overall_status"],
        "boot": boot_status,
        "systemd": systemd_status,
        "repository": repository_status,
        "storage": storage_status,
        "networking": networking_status,
        "dns": dns_status,
        "firewall": firewall_status,
        "ssh": ssh_status,
    }
    # The embedded kitpro-health result is authoritative. Detail fields help
    # locate a warning or error, but the inspector may not manufacture one.
    if document["overall_status"] == "healthy":
        return {
            name: (status if status == "unavailable" else "healthy")
            for name, status in summary.items()
        }
    return summary
