#!/usr/bin/env python3
"""Report whether this host can build and validate KITPro Linux media."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tools import kitpro_repo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_BUILD_COMMANDS = (
    "mkarchiso", "pacman", "python", "git", "gpg", "xorriso", "mksquashfs", "bsdtar",
)
REQUIRED_ACCEPTANCE_COMMANDS = (
    "qemu-system-x86_64", "parted", "ssh", "ssh-keygen",
)
OPTIONAL_COMMANDS = ("shellcheck", "kvm-ok")
OVMF_CANDIDATES = (
    Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
    Path("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
)


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _capture(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), "unavailable")


def _package_version(name: str) -> str:
    line = _capture(["pacman", "-Q", name])
    parts = line.split()
    return parts[1] if len(parts) == 2 and parts[0] == name else "unavailable"


def _subordinate_ids(path: Path) -> bool:
    if os.geteuid() == 0:
        return True
    try:
        user = __import__("pwd").getpwuid(os.getuid()).pw_name
        return any(line.split(":", 1)[0] == user for line in path.read_text().splitlines())
    except (KeyError, OSError):
        return False


def _mount_namespace() -> bool:
    try:
        return subprocess.run(
            ["unshare", "--mount", "true"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _filesystem(path: Path) -> str:
    return _capture(["findmnt", "-no", "FSTYPE", "--target", str(path)])


def _cgroup_memory_limit() -> int | None:
    try:
        value = Path("/sys/fs/cgroup/memory.max").read_text().strip()
        return None if value == "max" else int(value)
    except (OSError, ValueError):
        return None


def build_report(workspace: Path, *, require_acceptance: bool = True) -> dict[str, Any]:
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    commands = {
        name: shutil.which(name)
        for name in (*REQUIRED_BUILD_COMMANDS, *REQUIRED_ACCEPTANCE_COMMANDS, *OPTIONAL_COMMANDS)
    }
    missing_build = [name for name in REQUIRED_BUILD_COMMANDS if not commands[name]]
    missing_acceptance = [name for name in REQUIRED_ACCEPTANCE_COMMANDS if not commands[name]]
    firmware = next((path for path in OVMF_CANDIDATES if path.is_file()), None)
    arch_supported = platform.machine() == "x86_64"
    os_supported = os_release.get("ID") == "arch"
    mount_namespace = _mount_namespace()
    privilege_model = "root" if os.geteuid() == 0 else "unprivileged-userns"
    can_build = not missing_build and mount_namespace and (os.geteuid() == 0 or (
        _subordinate_ids(Path("/etc/subuid")) and _subordinate_ids(Path("/etc/subgid"))
    ))
    can_accept = not missing_acceptance and firmware is not None
    if not os_supported or not arch_supported:
        status = "unsupported"
    elif not can_build or (require_acceptance and not can_accept):
        status = "unqualified"
    elif not Path("/dev/kvm").exists():
        status = "usable_degraded"
    else:
        status = "qualified"
    memory_bytes = 0
    try:
        match = re.search(r"^MemTotal:\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.MULTILINE)
        if match:
            memory_bytes = int(match.group(1)) * 1024
    except OSError:
        pass
    disk = shutil.disk_usage(workspace)
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "status": status,
        "worker": {
            "hostname": platform.node(),
            "os_id": os_release.get("ID", "unknown"),
            "os_build_id": os_release.get("BUILD_ID", "unknown"),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "systemd": _capture(["systemctl", "--version"]),
            "pacman": _package_version("pacman"),
            "archiso": _package_version("archiso"),
            "qemu": _capture(["qemu-system-x86_64", "--version"]),
            "ovmf": _package_version("edk2-ovmf"),
            "git": _capture(["git", "--version"]),
            "filesystem": _filesystem(workspace),
            "memory_bytes": memory_bytes,
            "memory_limit_bytes": _cgroup_memory_limit(),
            "free_disk_bytes": disk.free,
            "environment": "container" if Path("/.dockerenv").exists() else "host-or-vm",
        },
        "capabilities": {
            "privilege_model": privilege_model,
            "mount_namespace": mount_namespace,
            "subuid": _subordinate_ids(Path("/etc/subuid")),
            "subgid": _subordinate_ids(Path("/etc/subgid")),
            "kvm": Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK),
            "tcg": commands["qemu-system-x86_64"] is not None,
            "ovmf_code": str(firmware) if firmware else None,
            "can_build_media": can_build,
            "can_run_acceptance": can_accept,
        },
        "commands": commands,
        "missing_required_build_commands": missing_build,
        "missing_required_acceptance_commands": missing_acceptance,
        "degraded_capabilities": ([] if Path("/dev/kvm").exists() else ["kvm"]),
    }
    report["report_sha256"] = kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(report))
    return report


def validate_report(report: dict[str, Any], *, allow_degraded: bool = True) -> None:
    if report.get("schema_version") != 1:
        raise kitpro_repo.PipelineError("unsupported worker report schema")
    allowed = {"qualified", "usable_degraded"} if allow_degraded else {"qualified"}
    if report.get("status") not in allowed:
        raise kitpro_repo.PipelineError(f"worker is not usable: {report.get('status')}")
    expected = dict(report)
    digest = expected.pop("report_sha256", None)
    if digest != kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(expected)):
        raise kitpro_repo.PipelineError("worker capability report hash is invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--require-kvm", action="store_true")
    args = parser.parse_args()
    try:
        report = build_report(args.workspace.resolve(), require_acceptance=not args.build_only)
        if args.output:
            kitpro_repo.atomic_write_json(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        validate_report(report, allow_degraded=not args.require_kvm)
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
