#!/usr/bin/env python3
"""Read-mostly KITPro Linux rescue inspection and explicit repair commands."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from tools import kitpro_phase2, kitpro_repo
from tools.offline_support import (
    MOUNTINFO,
    validate_mount_boundary,
    validate_output_destination,
    validate_target_surface,
)
from tools.system_health import validate_health_report
from tools.support_bundle import validate_manifest
from tools.install.receipt import validate_receipt
from tools.install.render import loader_entry


DEFAULT_MOUNT_ROOT = Path("/run/kitpro-rescue")
SAFE_PACKAGE = re.compile(r"^[a-z0-9@._+:-]+$")
KERNEL_STATE_PATH = Path("var/lib/kitpro-linux/kernel-state.json")
KERNEL_RUNTIME = "/usr/lib/kitpro-linux/kernel-lifecycle"
DEVELOPMENT_KERNEL_RUNTIME = Path(__file__).resolve().parents[1] / "runtime/kernel-lifecycle"
DEVELOPMENT_SYSTEM_HEALTH_RUNTIME = Path(__file__).resolve().parents[1] / "runtime/system-health"
DEVELOPMENT_SUPPORT_BUNDLE_RUNTIME = Path(__file__).resolve().parents[1] / "runtime/support-bundle"
MEDIA_BUILD_CONFIGURATION = Path("/opt/kitpro-linux/media/build-configuration.json")


def _now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_recovery_receipt(document: dict[str, Any]) -> None:
    required = {
        "schema_version", "kind", "operation", "target", "release", "generation",
        "started_at", "completed_at", "changes", "result", "validation",
        "receipt_sha256",
    }
    if set(document) != required:
        raise kitpro_repo.PipelineError("recovery receipt fields do not match schema version 1")
    if document["schema_version"] != 1 or document["kind"] != "kitpro-recovery-receipt":
        raise kitpro_repo.PipelineError("unsupported recovery receipt")
    if document["result"] not in {"passed", "failed"}:
        raise kitpro_repo.PipelineError("recovery receipt has an invalid result")
    if not isinstance(document["changes"], list) or not all(
        isinstance(item, str) for item in document["changes"]
    ):
        raise kitpro_repo.PipelineError("recovery receipt changes must be strings")
    digest = document.get("receipt_sha256")
    value = dict(document)
    value.pop("receipt_sha256", None)
    if digest != kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(value)):
        raise kitpro_repo.PipelineError("recovery receipt hash is invalid")


def _os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(errors="replace").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def _safe_json(path: Path) -> dict[str, Any] | None:
    try:
        value = kitpro_repo.load_json(path)
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def detect_root(root: Path, device: str = "mounted-root", filesystem: str = "unknown") -> dict[str, Any] | None:
    """Identify one already-mounted KITPro root without modifying it."""
    root = root.resolve()
    os_release = _os_release(root / "etc/os-release")
    if os_release.get("ID") != "kitpro-linux":
        return None
    release = _safe_json(root / "etc/kitpro-linux-release.json") or {}
    receipt = _safe_json(root / "var/lib/kitpro-linux/install-receipt.json")
    receipt_valid = False
    if receipt is not None:
        try:
            validate_receipt(receipt)
            receipt_valid = True
        except kitpro_repo.PipelineError:
            pass
    return {
        "device": device,
        "filesystem": filesystem,
        "mount": str(root),
        "mount_policy": "caller-provided",
        "release": release.get("release") or os_release.get("VERSION_ID"),
        "generation": release.get("generation") or os_release.get("BUILD_ID"),
        "hostname": (root / "etc/hostname").read_text(errors="replace").strip()
        if (root / "etc/hostname").is_file()
        else None,
        "boot_layout": "uefi-systemd-boot"
        if (root / "efi/loader").is_dir()
        else "not-detected",
        "install_receipt": "valid" if receipt_valid else ("invalid" if receipt else "missing"),
    }


def _lsblk_partitions() -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            "lsblk", "-J", "-p", "-o",
            "PATH,TYPE,FSTYPE,LABEL,PARTUUID,MOUNTPOINTS",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(f"cannot enumerate rescue candidates: {completed.stderr.strip()}")

    def flatten(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in items:
            result.append(item)
            result.extend(flatten(item.get("children", [])))
        return result

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("lsblk returned invalid JSON") from error
    return [
        item
        for item in flatten(document.get("blockdevices", []))
        if item.get("type") == "part" and item.get("fstype") == "ext4"
    ]


def detect_installations(mount_root: Path = DEFAULT_MOUNT_ROOT) -> list[dict[str, Any]]:
    """Mount candidate ext4 partitions read-only, identify KITPro roots, then unmount."""
    if os.geteuid() != 0:
        raise kitpro_repo.PipelineError("automatic rescue detection requires root privileges")
    mount_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    found: list[dict[str, Any]] = []
    for number, item in enumerate(_lsblk_partitions(), 1):
        device = str(item["path"])
        existing = [value for value in (item.get("mountpoints") or []) if value]
        mounted_here = False
        if existing:
            candidate = Path(existing[0])
            policy = "existing-mount"
        else:
            candidate = mount_root / f"candidate-{number}"
            candidate.mkdir(mode=0o700)
            completed = subprocess.run(
                ["mount", "-o", "ro,nosuid,nodev,noexec", device, str(candidate)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                candidate.rmdir()
                continue
            mounted_here = True
            policy = "temporary-read-only"
        try:
            detected = detect_root(candidate, device, str(item.get("fstype")))
            if detected:
                detected["mount_policy"] = policy
                found.append(detected)
        finally:
            if mounted_here:
                subprocess.run(["umount", str(candidate)], check=False)
                candidate.rmdir()
    return found


def _repository_check(root: Path, generation: str | None) -> dict[str, Any]:
    path = root / "etc/pacman.conf"
    try:
        repositories = kitpro_phase2.validate_repository_isolation(path)
        text = path.read_text()
        if generation and re.fullmatch(r"1\.0-g[0-9]{4}", generation):
            from tools.production_repository import production_pacman_config
            valid = repositories == ["kitpro-1.0-core"] and text == production_pacman_config()
            return {"valid": valid, "enabled": repositories, "pinned_generation": False,
                    "generation_policy": "current"}
        pinned = bool(generation and f"/{generation}/" in text and "/current/" not in text)
        valid = len(repositories) == 1 and repositories[0].startswith("kitpro-") and pinned
        return {"valid": valid, "enabled": repositories, "pinned_generation": pinned}
    except (kitpro_repo.PipelineError, OSError) as error:
        return {"valid": False, "error": str(error), "enabled": []}


def kernel_status(root: Path, running_kernel: str = "unavailable") -> tuple[dict[str, Any], int]:
    """Run the authoritative read-only lifecycle status against a mounted target."""
    root = root.resolve()
    target_runtime = root / KERNEL_RUNTIME.removeprefix("/")
    runtime = target_runtime if target_runtime.is_file() else DEVELOPMENT_KERNEL_RUNTIME
    completed = subprocess.run(
        [
            "/usr/bin/bash", str(runtime), "--root", str(root), "status", "--json",
            "--running-kernel", running_kernel,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in {0, 1, 2}:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise kitpro_repo.PipelineError(
            f"kernel status command failed ({completed.returncode}): {detail}"
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("kernel status command returned invalid JSON") from error
    if not isinstance(document, dict) or document.get("kind") != "kitpro-kernel-status":
        raise kitpro_repo.PipelineError("kernel status command returned an unsupported report")
    return document, completed.returncode


def health_report(root: Path) -> tuple[dict[str, Any], int]:
    """Run trusted live-media diagnostics against mounted target data."""
    root = root.resolve()
    environment = os.environ.copy()
    environment["KITPRO_KERNEL_LIFECYCLE"] = str(DEVELOPMENT_KERNEL_RUNTIME)
    completed = subprocess.run(
        [
            "/usr/bin/bash", str(DEVELOPMENT_SYSTEM_HEALTH_RUNTIME),
            "--root", str(root), "--mode", "offline", "--json",
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in {0, 1, 2}:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise kitpro_repo.PipelineError(
            f"system health command failed ({completed.returncode}): {detail}"
        )
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("system health command returned invalid JSON") from error
    if not isinstance(document, dict) or document.get("kind") != "kitpro-system-health":
        raise kitpro_repo.PipelineError("system health command returned an unsupported report")
    validate_health_report(document)
    if document.get("mode") != "offline":
        raise kitpro_repo.PipelineError("rescue health report did not use offline semantics")
    return document, completed.returncode


def _rescue_source_identity() -> tuple[str | None, str]:
    """Identify the trusted rescue runtime, never the mounted target."""
    configuration = _safe_json(MEDIA_BUILD_CONFIGURATION) if MEDIA_BUILD_CONFIGURATION.is_file() else {}
    commit = configuration.get("source_git_commit")
    media_version = configuration.get("media_version")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=Path(__file__).resolve().parents[1],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        candidate = completed.stdout.strip()
        commit = candidate if completed.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", candidate) else None
    if not isinstance(media_version, str) or not media_version:
        media_version = "unversioned-rescue-runtime"
    return commit, media_version


def support_bundle(
    root: Path,
    output: Path,
    esp: Path | None = None,
    overwrite: bool = False,
    mountinfo_path: Path = MOUNTINFO,
) -> tuple[dict[str, Any], int]:
    """Create a sanitized bundle while treating a mounted target as data only."""
    mount = validate_mount_boundary(root, esp, mountinfo_path)
    root = Path(mount["root"])
    esp_root = Path(mount["esp"]) if mount["esp"] else None
    output = validate_output_destination(
        output,
        [path for path in (root, esp_root) if path is not None],
    )
    surface = validate_target_surface(root)
    if detect_root(root) is None:
        raise kitpro_repo.PipelineError("target is not a KITPro Linux installation")
    runtime = DEVELOPMENT_SUPPORT_BUNDLE_RUNTIME
    if not runtime.is_file():
        raise kitpro_repo.PipelineError("trusted support-bundle runtime is unavailable")
    source_commit, media_version = _rescue_source_identity()
    environment = os.environ.copy()
    environment.update(
        {
            "KITPRO_SUPPORT_TEST_ROOT": str(root),
            "KITPRO_SUPPORT_MODE": "offline-rescue",
            "KITPRO_SYSTEM_HEALTH_COMMAND": str(DEVELOPMENT_SYSTEM_HEALTH_RUNTIME),
            "KITPRO_KERNEL_LIFECYCLE": str(DEVELOPMENT_KERNEL_RUNTIME),
            "KITPRO_SUPPORT_SOURCE_GIT_COMMIT": source_commit or "",
            "KITPRO_SUPPORT_SOURCE_PACKAGE_BUILD": media_version,
        }
    )
    command = ["/usr/bin/bash", str(runtime), "--output", str(output)]
    if overwrite:
        command.append("--overwrite")
    completed = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode not in {0, 1}:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise kitpro_repo.PipelineError(
            f"offline support bundle failed ({completed.returncode}): {detail}"
        )
    if not output.is_file() or output.is_symlink():
        raise kitpro_repo.PipelineError("offline support bundle did not produce a regular archive")
    manifest_result = subprocess.run(
        ["/usr/bin/tar", "--zstd", "-xOf", str(output), "manifest.json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if manifest_result.returncode != 0:
        raise kitpro_repo.PipelineError("offline support bundle manifest is unreadable")
    try:
        manifest = json.loads(manifest_result.stdout)
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("offline support bundle manifest is invalid JSON") from error
    validate_manifest(manifest)
    result = {
        "schema_version": 1,
        "kind": "kitpro-rescue-support-bundle-result",
        "mode": "offline-rescue",
        "target": mount,
        "target_surface": surface,
        "source": {
            "runtime": str(runtime),
            "git_commit": source_commit,
            "media_version": media_version,
            "target_binaries_executed": False,
        },
        "archive": str(output),
        "archive_size": output.stat().st_size,
        "archive_sha256": kitpro_repo.sha256_file(output),
        "collector_exit_code": completed.returncode,
        "bundle": {
            "bundle_id": manifest["bundle_id"],
            "collector_count": len(manifest["collectors"]),
            "file_count": len(manifest["files"]),
            "status": manifest["collector_result"],
            "health_status": manifest["health"]["overall_status"],
            "secret_scan": manifest["secret_scan"]["status"],
        },
    }
    return result, completed.returncode


def inspect_kernel_state(root: Path) -> dict[str, Any]:
    """Compatibility view backed by the shared lifecycle status implementation."""
    report, _exit_code = kernel_status(root)
    current_status = report["current"]
    previous_status = report["previous_known_good"]
    current = {
        "package_version": current_status["package_version"],
        "kernel_release": current_status["kernel_release"],
        "kernel_path": current_status["kernel_path"],
        "kernel_sha256": current_status["kernel_sha256"],
        "kernel_valid": current_status["kernel_valid"],
        "initramfs_path": current_status["initramfs_path"],
        "initramfs_sha256": current_status["initramfs_sha256"],
        "initramfs_valid": current_status["initramfs_valid"],
        "module_tree": current_status["module_tree"],
        "module_tree_present": current_status["module_tree_valid"],
        "boot_entry": current_status["boot_entry"],
        "boot_entry_valid": current_status["boot_entry_valid"],
    }
    previous_present = previous_status["present"]
    previous = {
        "available": previous_present,
        "package_version": previous_status["package_version"],
        "kernel_release": previous_status["kernel_release"],
        "kernel_path": previous_status["kernel_path"],
        "kernel_sha256": previous_status["kernel_sha256"],
        "kernel_valid": previous_status["kernel_valid"] if previous_present else True,
        "initramfs_path": previous_status["initramfs_path"],
        "initramfs_sha256": previous_status["initramfs_sha256"],
        "initramfs_valid": previous_status["initramfs_valid"] if previous_present else True,
        "module_tree": previous_status["module_tree"],
        "module_tree_present": previous_status["module_tree_valid"] if previous_present else True,
        "boot_entry": previous_status["boot_entry"],
        "boot_entry_valid": previous_status["boot_entry_valid"] if previous_present else True,
    }
    return {
        "present": (root / KERNEL_STATE_PATH).is_file(),
        "valid": (
            report["metadata_consistency"]
            and all(current[key] for key in (
                "kernel_valid", "initramfs_valid", "module_tree_present", "boot_entry_valid"
            ))
            and all(previous[key] for key in (
                "kernel_valid", "initramfs_valid", "module_tree_present", "boot_entry_valid"
            ))
        ),
        "state": current_status["state"],
        "candidate_status": report["candidate"]["status"] or "validated",
        "source_repository_generation": current_status["repository_generation"],
        "last_successful_boot": None,
        "last_successful_boot_kernel": None,
        "last_successful_boot_role": None,
        "transition_stage": report["transition_stage"],
        "current": current,
        "previous": previous,
    }


def inspect_root(root: Path) -> dict[str, Any]:
    """Build a sanitized health report without asserting offline filesystem integrity."""
    detected = detect_root(root)
    if detected is None:
        raise kitpro_repo.PipelineError(f"not a KITPro Linux installation: {root}")
    root = root.resolve()
    receipt = _safe_json(root / "var/lib/kitpro-linux/install-receipt.json") or {}
    root_partuuid = receipt.get("partitions", {}).get("root_partuuid")
    kernel_lifecycle = inspect_kernel_state(root)
    entry_path = root / "efi/loader/entries/kitpro-linux.conf"
    entry = entry_path.read_text(errors="replace") if entry_path.is_file() else ""
    boot = {
        "kernel": (root / "boot/vmlinuz-linux-lts").is_file(),
        "initramfs": (root / "boot/initramfs-linux-lts.img").is_file(),
        "efi_kernel": bool(kernel_lifecycle.get("current", {}).get("kernel_valid")),
        "efi_initramfs": bool(kernel_lifecycle.get("current", {}).get("initramfs_valid")),
        "loader_configuration": (root / "efi/loader/loader.conf").is_file(),
        "loader_entry": entry_path.is_file(),
        "root_identifier": bool(root_partuuid and f"root=PARTUUID={root_partuuid}" in entry),
    }
    network_files = sorted((root / "etc/systemd/network").glob("*.network"))
    network_valid = any(
        "[Match]" in path.read_text(errors="replace")
        and "[Network]" in path.read_text(errors="replace")
        for path in network_files
    )
    resolv = root / "etc/resolv.conf"
    resolver_valid = resolv.is_symlink() and os.readlink(resolv) == "../run/systemd/resolve/stub-resolv.conf"
    nft_path = root / "etc/nftables.conf"
    nft_text = nft_path.read_text(errors="replace") if nft_path.is_file() else ""
    nft_valid = all(
        value in nft_text
        for value in ('iifname "lo" accept', "established,related", "policy drop")
    )
    ssh_path = root / "etc/ssh/sshd_config.d/10-kitpro-server.conf"
    ssh_text = ssh_path.read_text(errors="replace") if ssh_path.is_file() else ""
    ssh_valid = all(
        value in ssh_text
        for value in (
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
        )
    )
    repository = _repository_check(root, detected["generation"])
    package_db = root / "var/lib/pacman/local"
    journal_directory = root / "var/log/journal"
    journal_summary: dict[str, Any] = {
        "persistent_directory": journal_directory.is_dir(),
        "failed_unit_events": "unavailable",
    }
    if journal_directory.is_dir() and any(journal_directory.rglob("*.journal")):
        completed = subprocess.run(
            [
                "journalctl", f"--directory={journal_directory}", "--no-pager",
                "--grep=Failed to (start|mount)", "--output=short-monotonic",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if completed.returncode in {0, 1}:
            journal_summary["failed_unit_events"] = len(
                [line for line in completed.stdout.splitlines() if line.strip()]
            )
    checks = {
        "identity": True,
        "release_metadata": (root / "etc/kitpro-linux-release.json").is_file(),
        "install_receipt": detected["install_receipt"] == "valid",
        "kernel_state": kernel_lifecycle["valid"],
        "kernel": boot["kernel"],
        "initramfs": boot["initramfs"] and boot["efi_initramfs"],
        "boot_entry": boot["loader_entry"] and boot["root_identifier"],
        "repository": repository["valid"],
        "package_database": package_db.is_dir(),
        "network": network_valid,
        "resolver": resolver_valid,
        "nftables": nft_valid,
        "sshd": ssh_valid,
    }
    return {
        "schema_version": 1,
        "kind": "kitpro-rescue-health",
        "generated_at": _now(),
        "status": "healthy" if all(checks.values()) else "degraded",
        "installation": detected,
        "checks": checks,
        "boot": boot,
        "kernel_lifecycle": kernel_lifecycle,
        "repository": repository,
        "packages": {
            "database_present": package_db.is_dir(),
            "installed_entries": len(list(package_db.iterdir())) if package_db.is_dir() else 0,
        },
        "network": {
            "configuration_files": [str(path.relative_to(root)) for path in network_files],
            "valid": network_valid,
            "resolved_symlink": resolver_valid,
        },
        "nftables": {"valid": nft_valid, "path": "/etc/nftables.conf"},
        "sshd": {"valid": ssh_valid, "path": "/etc/ssh/sshd_config.d/10-kitpro-server.conf"},
        "journal": journal_summary,
        "filesystem": {
            "integrity": "not-checked",
            "note": "Run the filesystem-specific checker offline; detection is not an integrity check.",
        },
    }


def require_confirmation(actual: str, expected: str) -> None:
    if actual != expected:
        raise kitpro_repo.PipelineError(f"write operation requires exact confirmation: {expected}")


def _run(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"recovery command failed ({completed.returncode}): {' '.join(command)}\n{completed.stdout}"
        )


def _receipt(
    root: Path,
    operation: str,
    started: str,
    changes: list[str],
    validation: dict[str, Any],
    result: str = "passed",
) -> tuple[Path, dict[str, Any]]:
    installation = detect_root(root)
    if installation is None:
        raise kitpro_repo.PipelineError("recovery receipt target is not KITPro Linux")
    document = {
        "schema_version": 1,
        "kind": "kitpro-recovery-receipt",
        "operation": operation,
        "target": str(root.resolve()),
        "release": installation["release"],
        "generation": installation["generation"],
        "started_at": started,
        "completed_at": _now(),
        "changes": changes,
        "result": result,
        "validation": validation,
    }
    document["receipt_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(document)
    )
    validate_recovery_receipt(document)
    directory = root / "var/lib/kitpro-linux/recovery"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    filename = f"{started.replace(':', '').replace('-', '')}-{operation}.json"
    path = directory / filename
    kitpro_repo.atomic_write_json(path, document)
    return path, document


def _require_mounted_esp(root: Path) -> None:
    esp = root / "efi"
    if not os.path.ismount(esp):
        raise kitpro_repo.PipelineError(
            f"ESP must be explicitly mounted at {esp} before boot or initramfs repair"
        )
    if not os.access(esp, os.W_OK):
        raise kitpro_repo.PipelineError(f"mounted ESP is not writable: {esp}")


def regenerate_initramfs(
    root: Path,
    confirmation: str,
    runner: Callable[[list[str]], None] = _run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    detect = detect_root(root)
    if detect is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    require_confirmation(confirmation, f"REGENERATE INITRAMFS {root}")
    _require_mounted_esp(root)
    started = _now()
    changes = ["/boot/initramfs-linux-lts.img", "/efi/initramfs-linux-lts.img"]
    try:
        runner(["arch-chroot", str(root), "mkinitcpio", "-P"])
        source = root / "boot/initramfs-linux-lts.img"
        if not source.is_file():
            raise kitpro_repo.PipelineError("mkinitcpio did not produce the linux-lts initramfs")
        lifecycle = inspect_kernel_state(root)
        if lifecycle["present"]:
            runner(["arch-chroot", str(root), KERNEL_RUNTIME, "refresh-current-artifacts"])
            destination = root / str(
                inspect_kernel_state(root)["current"]["initramfs_path"]
            ).removeprefix("/")
        else:
            destination = root / "efi/initramfs-linux-lts.img"
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        valid = source.is_file() and destination.is_file()
        return _receipt(
            root, "regenerate-initramfs", started, changes,
            {"initramfs_present": valid},
        )
    except Exception as error:
        _receipt(
            root, "regenerate-initramfs", started, changes,
            {"error": str(error)}, "failed",
        )
        raise


def repair_fallback_entry(
    root: Path,
    confirmation: str,
    runner: Callable[[list[str]], None] = _run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    if detect_root(root) is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    require_confirmation(confirmation, f"REPAIR FALLBACK ENTRY {root}")
    _require_mounted_esp(root)
    lifecycle = inspect_kernel_state(root)
    if not lifecycle.get("previous", {}).get("available"):
        raise kitpro_repo.PipelineError("no previous known-good kernel is recorded")
    started = _now()
    changes = ["/efi/loader/entries/kitpro-linux-previous.conf"]
    try:
        runner(["arch-chroot", str(root), KERNEL_RUNTIME, "repair-fallback-entry"])
        validation = inspect_kernel_state(root)["previous"]
        if not validation["boot_entry_valid"]:
            raise kitpro_repo.PipelineError("recreated fallback entry did not validate")
        return _receipt(root, "repair-fallback-entry", started, changes, validation)
    except Exception as error:
        _receipt(root, "repair-fallback-entry", started, changes, {"error": str(error)}, "failed")
        raise


def regenerate_previous_initramfs(
    root: Path,
    confirmation: str,
    runner: Callable[[list[str]], None] = _run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    if detect_root(root) is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    require_confirmation(confirmation, f"REGENERATE PREVIOUS INITRAMFS {root}")
    _require_mounted_esp(root)
    lifecycle = inspect_kernel_state(root)
    previous = lifecycle.get("previous", {})
    if not previous.get("available") or not previous.get("module_tree_present"):
        raise kitpro_repo.PipelineError("previous kernel modules are unavailable")
    started = _now()
    changes = [str(previous["initramfs_path"]), str(previous["boot_entry"])]
    try:
        runner(["arch-chroot", str(root), KERNEL_RUNTIME, "regenerate-previous-initramfs"])
        validation = inspect_kernel_state(root)["previous"]
        if not validation["initramfs_valid"] or not validation["boot_entry_valid"]:
            raise kitpro_repo.PipelineError("regenerated previous initramfs did not validate")
        return _receipt(root, "regenerate-previous-initramfs", started, changes, validation)
    except Exception as error:
        _receipt(
            root, "regenerate-previous-initramfs", started, changes,
            {"error": str(error)}, "failed",
        )
        raise


def repair_boot(
    root: Path,
    confirmation: str,
    runner: Callable[[list[str]], None] = _run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    installation = detect_root(root)
    if installation is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    require_confirmation(confirmation, f"REPAIR BOOT {root}")
    _require_mounted_esp(root)
    receipt = _safe_json(root / "var/lib/kitpro-linux/install-receipt.json")
    if receipt is None:
        raise kitpro_repo.PipelineError("boot repair requires a valid install receipt")
    validate_receipt(receipt)
    root_uuid = receipt["partitions"]["root_partuuid"]
    for path in (root / "boot/vmlinuz-linux-lts", root / "boot/initramfs-linux-lts.img"):
        if not path.is_file():
            raise kitpro_repo.PipelineError(f"boot repair source is missing: {path}")
    started = _now()
    changes = [
        "/efi/EFI/systemd",
        "/efi/loader/loader.conf",
        "/efi/loader/entries/kitpro-linux.conf",
        "/efi/loader/entries/kitpro-linux-compatibility.conf",
        "/efi/vmlinuz-linux-lts",
        "/efi/initramfs-linux-lts.img",
    ]
    try:
        runner(["bootctl", f"--root={root}", "--esp-path=/efi", "install"])
        (root / "efi/loader/entries").mkdir(parents=True, exist_ok=True)
        lifecycle = inspect_kernel_state(root)
        if lifecycle["present"]:
            runner(["arch-chroot", str(root), KERNEL_RUNTIME, "refresh-current-artifacts"])
        else:
            kitpro_repo.atomic_write(
                root / "efi/loader/loader.conf",
                b"default kitpro-linux.conf\ntimeout 3\nconsole-mode keep\n",
            )
            kitpro_repo.atomic_write(
                root / "efi/loader/entries/kitpro-linux.conf",
                loader_entry(root_uuid).encode(),
            )
            kitpro_repo.atomic_write(
                root / "efi/loader/entries/kitpro-linux-compatibility.conf",
                loader_entry(root_uuid, compatibility_graphics=True).encode(),
            )
            shutil.copy2(root / "boot/vmlinuz-linux-lts", root / "efi/vmlinuz-linux-lts")
            shutil.copy2(root / "boot/initramfs-linux-lts.img", root / "efi/initramfs-linux-lts.img")
        report = inspect_root(root)
        return _receipt(
            root, "repair-boot", started, changes,
            {"boot_entry": report["checks"]["boot_entry"], "initramfs": report["checks"]["initramfs"]},
        )
    except Exception as error:
        _receipt(root, "repair-boot", started, changes, {"error": str(error)}, "failed")
        raise


def reinstall_package(
    root: Path,
    package: str,
    confirmation: str,
    runner: Callable[[list[str]], None] = _run,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    installation = detect_root(root)
    if installation is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    if not SAFE_PACKAGE.fullmatch(package):
        raise kitpro_repo.PipelineError("package name is invalid")
    repository = _repository_check(root, installation["generation"])
    if not repository["valid"]:
        raise kitpro_repo.PipelineError("package recovery requires a valid pinned KITPro repository")
    require_confirmation(confirmation, f"REINSTALL {package} {root}")
    started = _now()
    changes = [f"package:{package}"]
    try:
        runner(["arch-chroot", str(root), "pacman", "-S", "--noconfirm", package])
        return _receipt(
            root, "reinstall-package", started, changes,
            {"repository_generation": installation["generation"], "package": package},
        )
    except Exception as error:
        _receipt(root, "reinstall-package", started, changes, {"error": str(error)}, "failed")
        raise


def verify_packages(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if detect_root(root) is None:
        raise kitpro_repo.PipelineError("target is not KITPro Linux")
    completed = subprocess.run(
        ["arch-chroot", str(root), "pacman", "-Qk"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    missing = [line for line in completed.stdout.splitlines() if "missing file" in line]
    return {
        "status": "passed" if completed.returncode == 0 and not missing else "failed",
        "returncode": completed.returncode,
        "missing_file_count": len(missing),
        "output_sha256": kitpro_repo.sha256_bytes(completed.stdout.encode()),
    }


def mount_installation(device: Path, destination: Path, read_write: bool, confirmation: str | None) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise kitpro_repo.PipelineError("mounting an installation requires root privileges")
    device = device.resolve(strict=True)
    destination = destination.resolve()
    if read_write:
        require_confirmation(confirmation or "", f"MOUNT READ-WRITE {device}")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    options = "rw,nosuid,nodev" if read_write else "ro,nosuid,nodev,noexec"
    _run(["mount", "-o", options, str(device), str(destination)])
    detected = detect_root(destination, str(device), "unknown")
    if detected is None:
        _run(["umount", str(destination)])
        raise kitpro_repo.PipelineError("mounted filesystem is not KITPro Linux")
    detected["mount_policy"] = "explicit-read-write" if read_write else "explicit-read-only"
    return detected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    detect = commands.add_parser("detect")
    detect.add_argument("--root", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--root", type=Path, required=True)
    check = commands.add_parser("check")
    check.add_argument("--root", type=Path, required=True)
    kernel = commands.add_parser("kernel-status")
    kernel.add_argument("--root", type=Path, required=True)
    health = commands.add_parser("health")
    health.add_argument("--root", type=Path, required=True)
    bundle = commands.add_parser("support-bundle")
    bundle.add_argument("--root", type=Path, required=True)
    bundle.add_argument("--esp", type=Path)
    bundle.add_argument("--output", type=Path, required=True)
    bundle.add_argument("--overwrite", action="store_true")
    mount = commands.add_parser("mount")
    mount.add_argument("device", type=Path)
    mount.add_argument("destination", type=Path)
    mount.add_argument("--read-write", action="store_true")
    mount.add_argument("--confirm-write")
    initramfs = commands.add_parser("regenerate-initramfs")
    initramfs.add_argument("--root", type=Path, required=True)
    initramfs.add_argument("--confirm-write", required=True)
    boot = commands.add_parser("repair-boot")
    boot.add_argument("--root", type=Path, required=True)
    boot.add_argument("--confirm-write", required=True)
    commands.add_parser("inspect-fallback").add_argument("--root", type=Path, required=True)
    fallback = commands.add_parser("repair-fallback-entry")
    fallback.add_argument("--root", type=Path, required=True)
    fallback.add_argument("--confirm-write", required=True)
    previous_initramfs = commands.add_parser("regenerate-previous-initramfs")
    previous_initramfs.add_argument("--root", type=Path, required=True)
    previous_initramfs.add_argument("--confirm-write", required=True)
    repository = commands.add_parser("verify-repository")
    repository.add_argument("--root", type=Path, required=True)
    packages = commands.add_parser("verify-packages")
    packages.add_argument("--root", type=Path, required=True)
    package = commands.add_parser("reinstall-package")
    package.add_argument("--root", type=Path, required=True)
    package.add_argument("package")
    package.add_argument("--confirm-write", required=True)
    commands.add_parser("shell")
    arguments = parser.parse_args()
    exit_code = 0
    try:
        if arguments.command == "detect":
            if arguments.root:
                result: Any = [detect_root(arguments.root)]
                result = [item for item in result if item is not None]
            else:
                result = detect_installations()
        elif arguments.command in {"inspect", "check"}:
            result = inspect_root(arguments.root)
        elif arguments.command == "kernel-status":
            result, exit_code = kernel_status(arguments.root)
        elif arguments.command == "health":
            result, exit_code = health_report(arguments.root)
        elif arguments.command == "support-bundle":
            mountinfo_path = Path(
                os.environ.get("KITPRO_RESCUE_TEST_MOUNTINFO", str(MOUNTINFO))
            )
            result, exit_code = support_bundle(
                arguments.root,
                arguments.output,
                arguments.esp,
                arguments.overwrite,
                mountinfo_path,
            )
        elif arguments.command == "mount":
            result = mount_installation(
                arguments.device,
                arguments.destination,
                arguments.read_write,
                arguments.confirm_write,
            )
        elif arguments.command == "regenerate-initramfs":
            path, receipt = regenerate_initramfs(arguments.root, arguments.confirm_write)
            result = {"receipt_path": str(path), "receipt": receipt}
        elif arguments.command == "repair-boot":
            path, receipt = repair_boot(arguments.root, arguments.confirm_write)
            result = {"receipt_path": str(path), "receipt": receipt}
        elif arguments.command == "inspect-fallback":
            result = inspect_kernel_state(arguments.root.resolve())
            if not result.get("previous", {}).get("available"):
                raise kitpro_repo.PipelineError("no previous known-good kernel is recorded")
        elif arguments.command == "repair-fallback-entry":
            path, receipt = repair_fallback_entry(arguments.root, arguments.confirm_write)
            result = {"receipt_path": str(path), "receipt": receipt}
        elif arguments.command == "regenerate-previous-initramfs":
            path, receipt = regenerate_previous_initramfs(
                arguments.root, arguments.confirm_write
            )
            result = {"receipt_path": str(path), "receipt": receipt}
        elif arguments.command == "verify-repository":
            detected = detect_root(arguments.root)
            if detected is None:
                raise kitpro_repo.PipelineError("target is not KITPro Linux")
            result = _repository_check(arguments.root.resolve(), detected["generation"])
            if not result["valid"]:
                raise kitpro_repo.PipelineError("repository validation failed")
        elif arguments.command == "verify-packages":
            result = verify_packages(arguments.root)
            if result["status"] != "passed":
                raise kitpro_repo.PipelineError("package verification failed")
        elif arguments.command == "reinstall-package":
            path, receipt = reinstall_package(
                arguments.root, arguments.package, arguments.confirm_write
            )
            result = {"receipt_path": str(path), "receipt": receipt}
        else:
            print("KITPro Linux Rescue maintenance shell", file=sys.stderr)
            print("Run 'kitpro-rescue detect' or 'kitpro-rescue --help'.", file=sys.stderr)
            os.execv("/bin/bash", ["/bin/bash", "-l"])
            raise AssertionError("unreachable")
        print(json.dumps(result, indent=2, sort_keys=True))
        return exit_code
    except (kitpro_repo.PipelineError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
