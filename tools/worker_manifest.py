#!/usr/bin/env python3
"""Describe and validate the pinned Phase 6 Arch build worker."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any

from tools import kitpro_repo


BASE_IMAGE_DIGEST = "sha256:8745817f349ed24373341ddb92776209eeec3f0364ea48f7f645ac5800d30a50"
ARCH_SNAPSHOT = "2026/09/24"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _sections(data: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    key: str | None = None
    for line in data.splitlines():
        if line.startswith("%") and line.endswith("%"):
            key = line.strip("%")
            result.setdefault(key, [])
        elif key and line:
            result[key].append(line)
    return result


def _installed_metadata_hash(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            relative = path.relative_to(root).as_posix()
            if relative == "desc":
                sections = _sections(path.read_text())
                # pacman records wall-clock installation time; it is not package identity.
                sections.pop("INSTALLDATE", None)
                digest = kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(sections))
            else:
                digest = kitpro_repo.sha256_file(path)
            records.append({"path": relative, "sha256": digest})
        elif path.is_symlink():
            records.append({
                "path": path.relative_to(root).as_posix(),
                "target": os.readlink(path),
            })
    return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(records))


def _sync_packages(sync_root: Path) -> dict[tuple[str, str], dict[str, str]]:
    packages: dict[tuple[str, str], dict[str, str]] = {}
    for database in sorted(sync_root.glob("*.db")):
        if database.is_symlink():
            database = database.resolve()
        with tarfile.open(database, "r:*") as archive:
            for member in archive.getmembers():
                if not member.isfile() or not member.name.endswith("/desc"):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                fields = _sections(extracted.read().decode())
                required = ("NAME", "VERSION", "FILENAME", "SHA256SUM")
                if not all(fields.get(field) for field in required):
                    continue
                record = {field.lower(): fields[field][0] for field in required}
                packages[(record["name"], record["version"])] = record
    return packages


def _installed_packages(local_root: Path, sync_root: Path) -> list[dict[str, str]]:
    synchronized = _sync_packages(sync_root)
    records: list[dict[str, str]] = []
    for desc in sorted(local_root.glob("*/desc")):
        fields = _sections(desc.read_text())
        if not fields.get("NAME") or not fields.get("VERSION"):
            raise kitpro_repo.PipelineError(f"invalid local package database entry: {desc}")
        name = fields["NAME"][0]
        version = fields["VERSION"][0]
        upstream = synchronized.get((name, version))
        if upstream is None:
            raise kitpro_repo.PipelineError(
                f"installed package is absent from pinned sync databases: {name} {version}"
            )
        records.append({
            "name": name,
            "version": version,
            "archive_filename": upstream["filename"],
            "archive_sha256": upstream["sha256sum"],
            "installed_metadata_sha256": _installed_metadata_hash(desc.parent),
        })
    return records


def _capture(command: list[str]) -> str:
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        raise kitpro_repo.PipelineError(f"cannot inspect worker tool: {' '.join(command)}")
    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")


def _package_version(name: str) -> str:
    output = _capture(["pacman", "-Q", name]).split()
    if len(output) != 2 or output[0] != name:
        raise kitpro_repo.PipelineError(f"cannot inspect worker package: {name}")
    return output[1]


def lock_document(
    *,
    local_root: Path = Path("/var/lib/pacman/local"),
    sync_root: Path = Path("/var/lib/pacman/sync"),
) -> dict[str, Any]:
    packages = _installed_packages(local_root, sync_root)
    databases = [
        {"filename": path.name, "sha256": kitpro_repo.sha256_file(path.resolve())}
        for path in sorted(sync_root.glob("*.db"))
    ]
    document: dict[str, Any] = {
        "schema_version": 1,
        "kind": "kitpro-phase6-worker-lock",
        "base_image_digest": BASE_IMAGE_DIGEST,
        "arch_snapshot": ARCH_SNAPSHOT,
        "architecture": platform.machine(),
        "package_count": len(packages),
        "packages": packages,
        "pacman_databases": databases,
        "tools": {
            "archiso": _package_version("archiso"),
            "dosfstools": _package_version("dosfstools"),
            "git": _package_version("git"),
            "gnupg": _package_version("gnupg"),
            "libisoburn": _package_version("libisoburn"),
            "mtools": _package_version("mtools"),
            "ovmf": _package_version("edk2-ovmf"),
            "pacman": _package_version("pacman"),
            "python": platform.python_version(),
            "qemu": _package_version("qemu-desktop"),
            "squashfs_tools": _package_version("squashfs-tools"),
            "systemd": _package_version("systemd"),
            "xorriso": _capture(["xorriso", "-version"]),
        },
        "requirements": {
            "minimum_memory_bytes": 8 * 1024**3,
            "minimum_free_storage_bytes": 80 * 1024**3,
            "privilege": "root-in-disposable-container",
            "mount_namespace": True,
            "kvm": "optional-for-portable-build-required-for-kvm-qualification",
        },
    }
    document["manifest_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(document)
    )
    return document


def validate_lock(document: dict[str, Any]) -> None:
    if document.get("schema_version") != 1 or document.get("kind") != "kitpro-phase6-worker-lock":
        raise kitpro_repo.PipelineError("unsupported worker lock")
    expected = dict(document)
    digest = expected.pop("manifest_sha256", None)
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise kitpro_repo.PipelineError("worker lock has no valid manifest hash")
    if digest != kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(expected)):
        raise kitpro_repo.PipelineError("worker lock manifest hash is invalid")
    if document.get("base_image_digest") != BASE_IMAGE_DIGEST:
        raise kitpro_repo.PipelineError("worker lock changed the base image digest")
    if document.get("arch_snapshot") != ARCH_SNAPSHOT:
        raise kitpro_repo.PipelineError("worker lock changed the Arch snapshot")
    if document.get("architecture") != "x86_64":
        raise kitpro_repo.PipelineError("worker lock has an unsupported architecture")
    packages = document.get("packages")
    if not isinstance(packages, list) or document.get("package_count") != len(packages):
        raise kitpro_repo.PipelineError("worker lock package count is invalid")
    for package in packages:
        if not HEX64.fullmatch(str(package.get("archive_sha256", ""))):
            raise kitpro_repo.PipelineError("worker lock contains an invalid package artifact hash")


def verify_running_worker(lock_path: Path) -> dict[str, Any]:
    expected = kitpro_repo.load_json(lock_path)
    validate_lock(expected)
    actual = lock_document()
    if actual != expected:
        expected_packages = {(p["name"], p["version"]) for p in expected["packages"]}
        actual_packages = {(p["name"], p["version"]) for p in actual["packages"]}
        changed_fields = sorted(
            key for key in set(expected) | set(actual)
            if key not in {"packages", "manifest_sha256"} and expected.get(key) != actual.get(key)
        )
        expected_by_name = {p["name"]: p for p in expected["packages"]}
        actual_by_name = {p["name"]: p for p in actual["packages"]}
        changed_packages = sorted(
            name for name in expected_by_name.keys() & actual_by_name.keys()
            if expected_by_name[name] != actual_by_name[name]
        )
        raise kitpro_repo.PipelineError(
            "running worker differs from lock: "
            f"missing={sorted(expected_packages - actual_packages)} "
            f"unexpected={sorted(actual_packages - expected_packages)} "
            f"changed_fields={changed_fields} changed_packages={changed_packages}"
        )
    image_digest = os.environ.get("KITPRO_WORKER_IMAGE_DIGEST", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest):
        raise kitpro_repo.PipelineError("KITPRO_WORKER_IMAGE_DIGEST is not an immutable image identity")
    result = dict(actual)
    result["kind"] = "kitpro-phase6-worker-manifest"
    result["worker_lock_sha256"] = expected["manifest_sha256"]
    result["worker_image_digest"] = image_digest
    result["host_kernel"] = platform.release()
    result["manifest_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes({k: v for k, v in result.items() if k != "manifest_sha256"})
    )
    return result


def verify_lock_matches_running_packages(lock_path: Path) -> dict[str, Any]:
    """Fail unless the installed worker package universe exactly matches the lock."""
    expected = kitpro_repo.load_json(lock_path)
    validate_lock(expected)
    actual = lock_document()
    if actual != expected:
        expected_packages = {(p["name"], p["version"]) for p in expected["packages"]}
        actual_packages = {(p["name"], p["version"]) for p in actual["packages"]}
        raise kitpro_repo.PipelineError(
            "running worker differs from lock: "
            f"missing={sorted(expected_packages - actual_packages)} "
            f"unexpected={sorted(actual_packages - expected_packages)}"
        )
    return actual


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    write = commands.add_parser("write-lock")
    write.add_argument("output", type=Path)
    validate = commands.add_parser("validate-lock")
    validate.add_argument("lock", type=Path)
    verify = commands.add_parser("verify-lock")
    verify.add_argument("lock", type=Path)
    report = commands.add_parser("report")
    report.add_argument("--lock", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "write-lock":
            result = lock_document()
            kitpro_repo.atomic_write_json(args.output, result)
        elif args.command == "validate-lock":
            result = kitpro_repo.load_json(args.lock)
            validate_lock(result)
        elif args.command == "verify-lock":
            result = verify_lock_matches_running_packages(args.lock)
        else:
            result = verify_running_worker(args.lock)
            kitpro_repo.atomic_write_json(args.output, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError, tarfile.TarError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
