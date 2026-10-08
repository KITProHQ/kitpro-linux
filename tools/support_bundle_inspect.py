#!/usr/bin/env python3
"""Validate and summarize an already extracted KITPro support bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

from tools.support_bundle import ValidationError, validate_health_payload, validate_manifest
from tools.system_health import subsystem_summary


INSPECTION_SCHEMA_VERSION = 1
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SUMMARY_FIELDS = {
    "schema_version", "kind", "archive", "manifest", "bundle", "health",
    "collection", "redaction", "source", "warning_count", "error_count",
    "warnings", "errors",
}
VIEW_LIMIT_BYTES = 1024 * 1024
VIEWABLE_EXACT_PATHS = {
    "health/system-health.json",
    "system/os-release.txt",
    "system/kitpro-release.json",
    "system/uname.txt",
    "system/uptime.txt",
    "system/systemd-failed.txt",
    "boot/bootctl-status.txt",
    "boot/bootctl-list.txt",
    "boot/kernel-status.json",
    "boot/kernel-state.json",
    "boot/loader.conf",
    "repository/pacman.conf",
    "repository/installed-packages.txt",
    "network/networkctl.txt",
    "network/ip-address.txt",
    "network/ip-route.txt",
    "network/resolvectl.txt",
    "network/resolv-conf-link.txt",
    "firewall/nftables.txt",
    "firewall/nftables.conf",
    "ssh/sshd-effective.txt",
    "ssh/sshd-policy.conf",
    "storage/mounts.txt",
    "storage/filesystems.txt",
    "storage/inodes.txt",
    "storage/fstab.txt",
    "hardware/cpu.txt",
    "hardware/memory.txt",
    "hardware/virtualization.txt",
    "hardware/block-devices.txt",
    "redaction/report.json",
}
VIEWABLE_PATH_PATTERNS = (
    re.compile(r"boot/loader-entries/kitpro-linux[A-Za-z0-9._-]*\.conf"),
    re.compile(r"network/config/[A-Za-z0-9._-]+\.network"),
    re.compile(r"receipts/(?:install-receipt|kernel-transition-[0-9]+|recovery-[0-9]+)\.json"),
    re.compile(r"logs/(?:journal-current-boot|journal-previous-boot|journal-kernel|journal-services)\.txt"),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json(path: Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"{name} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValidationError(f"{name} must be a JSON object")
    return value


def _exact_fields(value: dict[str, Any], fields: set[str], name: str) -> None:
    if set(value) != fields:
        raise ValidationError(f"{name} fields do not match format version 1")


def _validate_redaction(document: dict[str, Any], manifest: dict[str, Any]) -> None:
    _exact_fields(
        document,
        {"schema_version", "kind", "profile", "status", "total_replacements", "categories", "events", "omitted"},
        "redaction report",
    )
    if document.get("schema_version") != 1 or document.get("kind") != "kitpro-support-redaction-report":
        raise ValidationError("redaction report identity is invalid")
    if document.get("profile") != manifest["redaction_profile"] or document.get("status") != "sanitized":
        raise ValidationError("redaction report did not complete")
    if document.get("total_replacements") != manifest["redaction"]["total_replacements"]:
        raise ValidationError("redaction replacement count does not match the manifest")
    if document.get("categories") != manifest["redaction"]["categories"]:
        raise ValidationError("redaction categories do not match the manifest")
    if not isinstance(document.get("events"), list) or not isinstance(document.get("omitted"), list):
        raise ValidationError("redaction report lists are invalid")
    if not all(isinstance(item, str) for item in document["omitted"]):
        raise ValidationError("redaction omissions are invalid")
    total = 0
    for event in document["events"]:
        if not isinstance(event, dict) or set(event) != {"path", "category", "replacements"}:
            raise ValidationError("redaction event is invalid")
        if not isinstance(event["path"], str) or not isinstance(event["category"], str):
            raise ValidationError("redaction event labels are invalid")
        if not isinstance(event["replacements"], int) or event["replacements"] < 1:
            raise ValidationError("redaction event count is invalid")
        total += event["replacements"]
    if total != document["total_replacements"]:
        raise ValidationError("redaction event total is inconsistent")


def _validate_secret_scan(document: dict[str, Any]) -> None:
    _exact_fields(
        document,
        {"schema_version", "kind", "status", "scanned_file_count", "finding_count", "findings"},
        "secret scan report",
    )
    if document.get("schema_version") != 1 or document.get("kind") != "kitpro-support-secret-scan":
        raise ValidationError("secret scan report identity is invalid")
    if document.get("status") != "passed" or document.get("finding_count") != 0 or document.get("findings") != []:
        raise ValidationError("secret scan report did not pass")
    if not isinstance(document.get("scanned_file_count"), int) or document["scanned_file_count"] < 1:
        raise ValidationError("secret scan file count is invalid")


def validate_workspace(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate the semantic contract inside the verifier's private workspace."""
    if not root.is_dir() or root.is_symlink():
        raise ValidationError("verified bundle workspace is unavailable")
    manifest = _json(root / "manifest.json", "support bundle manifest")
    validate_manifest(manifest)

    health_path = root / manifest["health"]["path"]
    health = _json(health_path, "system health payload")
    validate_health_payload(health)
    if _sha256(health_path) != manifest["health"]["sha256"]:
        raise ValidationError("system health payload hash does not match the manifest")
    if health["overall_status"] != manifest["health"]["overall_status"]:
        raise ValidationError("system health status does not match the manifest")

    files = {item["path"]: item for item in manifest["files"]}
    expected = set(files)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "manifest.sha256"}
    }
    if actual != expected:
        raise ValidationError("payload inventory does not match the manifest")
    for relative, item in files.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValidationError("payload member is not a regular file")
        if path.stat().st_size != item["size_bytes"] or _sha256(path) != item["sha256"]:
            raise ValidationError("payload size or hash does not match the manifest")

    redaction_path = root / manifest["redaction"]["report"]
    scan_path = root / manifest["secret_scan"]["report"]
    if redaction_path.relative_to(root).as_posix() not in files:
        raise ValidationError("redaction report is absent from the payload inventory")
    if scan_path.relative_to(root).as_posix() not in files:
        raise ValidationError("secret scan report is absent from the payload inventory")
    redaction = _json(redaction_path, "redaction report")
    secret_scan = _json(scan_path, "secret scan report")
    _validate_redaction(redaction, manifest)
    _validate_secret_scan(secret_scan)
    return manifest, health, redaction, secret_scan


def is_viewable_member(path: str) -> bool:
    """Return whether a manifest path belongs to the explicit safe-view policy."""
    return path in VIEWABLE_EXACT_PATHS or any(pattern.fullmatch(path) for pattern in VIEWABLE_PATH_PATTERNS)


def viewable_members(root: Path) -> list[str]:
    """Return the canonical list of allowlisted members in a verified workspace."""
    manifest, _, _, _ = validate_workspace(root)
    return [item["path"] for item in manifest["files"] if is_viewable_member(item["path"])]


def _terminal_safe(value: str) -> str:
    output: list[str] = []
    for character in value:
        if character in {"\n", "\t"}:
            output.append(character)
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            codepoint = ord(character)
            output.append(f"\\x{codepoint:02x}" if codepoint <= 0xFF else f"\\u{codepoint:04x}")
            continue
        output.append(character)
    return "".join(output)


def render_member(root: Path, member: str, *, pretty: bool) -> tuple[str, bool]:
    """Render one allowlisted member from the verifier-owned workspace."""
    manifest, _, _, _ = validate_workspace(root)
    files = {item["path"]: item for item in manifest["files"]}
    if member not in files:
        raise ValidationError("requested member is not declared in the verified manifest")
    if not is_viewable_member(member):
        raise ValidationError("requested member is not allowlisted for viewing")
    item = files[member]
    if item["redaction_status"] != "sanitized":
        raise ValidationError("requested member is not marked sanitized")
    if item["size_bytes"] > VIEW_LIMIT_BYTES:
        raise ValidationError(f"requested member exceeds the {VIEW_LIMIT_BYTES}-byte display limit")
    path = root / member
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ValidationError("requested member cannot be read") from error
    if len(payload) != item["size_bytes"] or _sha256(path) != item["sha256"]:
        raise ValidationError("requested member changed after bundle verification")
    if b"\0" in payload:
        raise ValidationError("requested member contains NUL bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError("requested member is not valid UTF-8 text") from error
    if pretty:
        if not member.endswith(".json"):
            raise ValidationError("--pretty is supported only for JSON members")
        try:
            document = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValidationError("requested JSON member is invalid") from error
        text = json.dumps(document, sort_keys=True, indent=2) + "\n"
    safe_text = _terminal_safe(text)
    banner = (
        "KITPro Support Bundle Member\n\n"
        f"Bundle ID:          {manifest['bundle_id']}\n"
        f"Member:             {member}\n"
        "Sanitized:          yes\n"
        f"Truncated:          {'yes' if item['truncated'] else 'no'}\n"
        f"Size:               {item['size_bytes']} bytes\n\n"
    )
    return banner + safe_text + ("" if safe_text.endswith("\n") else "\n"), bool(item["truncated"])


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def build_summary(
    root: Path,
    *,
    archive_path: str,
    archive_sha256: str,
    archive_size: int,
    verbose: bool,
) -> dict[str, Any]:
    manifest, health, redaction, secret_scan = validate_workspace(root)
    if not SHA256.fullmatch(archive_sha256) or archive_size < 1:
        raise ValidationError("archive identity supplied by the verifier is invalid")
    collector_attention = []
    for collector in manifest["collectors"]:
        if collector["status"] != "collected" or collector["truncated"] or collector["timed_out"]:
            collector_attention.append(
                {
                    "id": collector["id"],
                    "status": collector["status"],
                    "truncated": collector["truncated"],
                    "timed_out": collector["timed_out"],
                }
            )
    warnings = list(manifest["warnings"]) + list(health["warnings"])
    warnings.extend(
        f"Collector {item['id']} is {item['status']}."
        for item in collector_attention
        if item["status"] != "collected"
    )
    warnings.extend(
        f"Collector {item['id']} output was truncated."
        for item in collector_attention
        if item["truncated"]
    )
    errors = list(manifest["errors"]) + list(health["errors"])
    files = manifest["files"]
    categories = sorted({item["path"].split("/", 1)[0] for item in files})
    logs = [
        {"path": item["path"], "size_bytes": item["size_bytes"], "truncated": item["truncated"]}
        for item in files
        if item["path"].startswith("logs/")
    ]
    source = manifest["source"]
    summary: dict[str, Any] = {
        "schema_version": INSPECTION_SCHEMA_VERSION,
        "kind": "kitpro-support-bundle-inspection",
        "archive": {
            "path": archive_path,
            "name": Path(archive_path).name,
            "size_bytes": archive_size,
            "sha256": archive_sha256,
            "verification": "passed",
        },
        "manifest": {
            "schema_version": manifest["schema_version"],
            "bundle_format_version": manifest["bundle_format_version"],
            "sha256": _sha256(root / "manifest.json"),
        },
        "bundle": {
            "id": manifest["bundle_id"],
            "mode": manifest["mode"],
            "created_at": manifest["created_at"],
            "product": manifest["product"]["name"],
            "release": manifest["product"]["release"],
            "generation": manifest["product"]["generation"],
            "architecture": manifest["product"]["architecture"],
            "kernel": manifest["product"]["kernel"],
        },
        "health": {
            "overall_status": health["overall_status"],
            "mode": health["mode"],
            "subsystems": subsystem_summary(health),
        },
        "collection": {
            "result": manifest["collector_result"],
            "collector_count": len(manifest["collectors"]),
            "payload_file_count": len(files),
            "truncation_count": sum(bool(item["truncated"]) for item in files),
            "collector_attention": collector_attention,
            "categories": categories,
            "logs": logs,
        },
        "redaction": {
            "profile": manifest["redaction_profile"],
            "result": redaction["status"],
            "total_replacements": redaction["total_replacements"],
            "omitted_category_count": len(redaction["omitted"]),
            "secret_scan": secret_scan["status"],
            "secret_finding_count": secret_scan["finding_count"],
        },
        "source": {
            "command_version": source["version"],
            "git_commit": source["git_commit"],
            "package_build": source["package_build"],
            "rescue_media_version": source["package_build"] if manifest["mode"] == "offline-rescue" else None,
        },
        "warning_count": len(_deduplicate(warnings)),
        "error_count": len(_deduplicate(errors)),
        "warnings": _deduplicate(warnings),
        "errors": _deduplicate(errors),
    }
    if verbose:
        summary["collection"]["included_files"] = [item["path"] for item in files]
        summary["collection"]["collectors"] = manifest["collectors"]
        summary["redaction"]["categories"] = redaction["categories"]
    validate_summary(summary, verbose=verbose)
    return summary


def validate_summary(summary: dict[str, Any], *, verbose: bool) -> None:
    _exact_fields(summary, SUMMARY_FIELDS, "inspection summary")
    if summary.get("schema_version") != 1 or summary.get("kind") != "kitpro-support-bundle-inspection":
        raise ValidationError("inspection summary identity is invalid")
    if summary["archive"].get("verification") != "passed" or not SHA256.fullmatch(summary["archive"].get("sha256", "")):
        raise ValidationError("inspection archive identity is invalid")
    if summary["manifest"].get("bundle_format_version") != 1:
        raise ValidationError("inspection summary uses an unsupported bundle format")
    if summary["health"].get("overall_status") not in {"healthy", "warning", "error", "unknown"}:
        raise ValidationError("inspection health status is invalid")
    collection_fields = {
        "result", "collector_count", "payload_file_count", "truncation_count",
        "collector_attention", "categories", "logs",
    }
    if verbose:
        collection_fields |= {"included_files", "collectors"}
    _exact_fields(summary["collection"], collection_fields, "inspection collection")
    redaction_fields = {
        "profile", "result", "total_replacements", "omitted_category_count",
        "secret_scan", "secret_finding_count",
    }
    if verbose:
        redaction_fields.add("categories")
    _exact_fields(summary["redaction"], redaction_fields, "inspection redaction")


def attention_required(summary: dict[str, Any]) -> bool:
    return bool(
        summary["health"]["overall_status"] != "healthy"
        or summary["collection"]["result"] != "complete"
        or summary["warning_count"]
        or summary["error_count"]
        or summary["collection"]["collector_attention"]
    )


def _human(summary: dict[str, Any], *, verbose: bool) -> str:
    bundle = summary["bundle"]
    archive = summary["archive"]
    health = summary["health"]
    collection = summary["collection"]
    redaction = summary["redaction"]
    lines = [
        "KITPro Support Bundle",
        "",
        f"Bundle ID:          {bundle['id']}",
        f"Created:            {bundle['created_at']}",
        f"Mode:               {bundle['mode']}",
        f"Product:            {bundle['product']}",
        f"Release:            {bundle['release'] or 'unavailable'}",
        f"Generation:         {bundle['generation'] or 'unavailable'}",
        f"Architecture:       {bundle['architecture']}",
        "",
        "Bundle",
        f"  Verification:     {archive['verification']}",
        f"  Files:            {collection['payload_file_count']}",
        f"  Archive size:     {archive['size_bytes']} bytes",
        f"  Archive SHA-256:  {archive['sha256']}",
        f"  Redaction:        {redaction['result']}",
        f"  Secret scan:      {redaction['secret_scan']}",
        "",
        "System health",
        f"  Overall:          {health['overall_status']}",
    ]
    labels = {"dns": "DNS", "ssh": "SSH", "systemd": "systemd"}
    for name, status in health["subsystems"].items():
        label = labels.get(name, name.capitalize())
        lines.append(f"  {label + ':':<18}{status}")
    lines.extend(
        [
            "",
            f"Warnings:           {summary['warning_count']}",
            f"Errors:             {summary['error_count']}",
        ]
    )
    for message in summary["warnings"]:
        lines.append(f"  WARNING: {message}")
    for message in summary["errors"]:
        lines.append(f"  ERROR: {message}")
    lines.extend(
        [
            "",
            "Collection",
            f"  Result:           {collection['result']}",
            f"  Collectors:       {collection['collector_count']}",
            f"  Truncated files:  {collection['truncation_count']}",
        ]
    )
    if bundle["mode"] == "offline-rescue":
        lines.append(f"  Rescue media:     {summary['source']['rescue_media_version'] or 'unavailable'}")
        lines.append("  Target runtime:   offline")
    if verbose:
        lines.extend(["", "Included files"])
        lines.extend(f"  {path}" for path in collection["included_files"])
        lines.extend(["", "Redaction categories"])
        lines.extend(f"  {category}" for category in summary["redaction"]["categories"])
        if collection["logs"]:
            lines.extend(["", "Logs"])
            lines.extend(
                f"  {item['path']}: {item['size_bytes']} bytes"
                + (" (truncated)" if item["truncated"] else "")
                for item in collection["logs"]
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="support-bundle-inspect-internal")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("workspace", type=Path)
    inventory = subparsers.add_parser("inventory")
    inventory.add_argument("workspace", type=Path)
    summarize = subparsers.add_parser("summarize")
    summarize.add_argument("workspace", type=Path)
    summarize.add_argument("--archive-path", required=True)
    summarize.add_argument("--archive-sha256", required=True)
    summarize.add_argument("--archive-size", required=True, type=int)
    summarize.add_argument("--json", action="store_true")
    summarize.add_argument("--verbose", action="store_true")
    members = subparsers.add_parser("members")
    members.add_argument("workspace", type=Path)
    view = subparsers.add_parser("view")
    view.add_argument("workspace", type=Path)
    view.add_argument("member")
    view.add_argument("--pretty", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command in {"validate", "inventory"}:
            manifest, _, _, _ = validate_workspace(arguments.workspace)
            if arguments.command == "inventory":
                for item in manifest["files"]:
                    print(item["path"], item["sha256"], item["size_bytes"])
            return 0
        if arguments.command == "members":
            for member in viewable_members(arguments.workspace):
                print(member)
            return 0
        if arguments.command == "view":
            output, truncated = render_member(
                arguments.workspace,
                arguments.member,
                pretty=arguments.pretty,
            )
            print(output, end="")
            return 1 if truncated else 0
        summary = build_summary(
            arguments.workspace,
            archive_path=arguments.archive_path,
            archive_sha256=arguments.archive_sha256,
            archive_size=arguments.archive_size,
            verbose=arguments.verbose,
        )
        if arguments.json:
            print(json.dumps(summary, sort_keys=True, indent=2))
        else:
            print(_human(summary, verbose=arguments.verbose), end="")
        return 1 if attention_required(summary) else 0
    except (OSError, ValidationError) as error:
        print(f"support bundle inspection failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
