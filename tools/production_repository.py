#!/usr/bin/env python3
"""Prototype KITPro Linux production repository publication and client config."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from tools import kitpro_repo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_HOSTNAME = "repo.kitpro.us"
PRODUCTION_BASE_URL = "https://repo.kitpro.us/kitpro-linux"
RELEASE = "1.0"
REPOSITORY_NAME = "kitpro-1.0-core"
ARCH = "x86_64"

FORBIDDEN_PRODUCTION_MARKERS = (
    "0.1-dev",
    "DEVELOPMENT",
    "KITPro Linux TEST",
    "dev-root@kitpro.invalid",
    "dev-package@kitpro.invalid",
    "dev-repository@kitpro.invalid",
    "kitpro-development-repository-ca",
)


def private_infrastructure_markers(text: str) -> list[str]:
    """Reject infrastructure categories without embedding operator inventory."""
    patterns = {
        'internal-hostname': r'(?i)(?:[a-z0-9_-]+\.)+(?:home|internal|local)\.[a-z0-9.-]+',
        'private-ipv4': r'(?<![\w.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\w.])',
        'operator-home-path': r'/(?:home|Users)/[a-zA-Z_][a-zA-Z0-9_-]*(?:/|\b)',
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, text)]


def generation_number(generation: str) -> int:
    match = re.fullmatch(r"1\.0-g([0-9]{4})", generation)
    if not match:
        raise kitpro_repo.PipelineError(f"invalid production generation: {generation}")
    return int(match.group(1))


def generation_path(generation: str) -> str:
    generation_number(generation)
    return f"stable/{RELEASE}/{generation}/core/os/$arch"


def production_pacman_config() -> str:
    return (
        "[options]\n"
        "HoldPkg = pacman glibc\n"
        "Architecture = auto\n"
        "CheckSpace\n"
        "ParallelDownloads = 5\n"
        "DownloadUser = alpm\n"
        "SigLevel = Required DatabaseRequired TrustedOnly\n"
        "LocalFileSigLevel = Required TrustedOnly\n\n"
        f"[{REPOSITORY_NAME}]\n"
        "SigLevel = Required DatabaseRequired TrustedOnly\n"
        f"Server = {PRODUCTION_BASE_URL}/stable/{RELEASE}/current/core/os/$arch\n"
    )


def contamination_findings(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir() or path.is_symlink():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError as error:
            findings.append({"path": path.relative_to(root).as_posix(), "marker": f"unreadable: {error}"})
            continue
        for marker in private_infrastructure_markers(text):
            findings.append({'path': path.relative_to(root).as_posix(), 'marker': marker})
        for marker in FORBIDDEN_PRODUCTION_MARKERS:
            if marker in text:
                findings.append({"path": path.relative_to(root).as_posix(), "marker": marker})
    return findings


def _copy_immutable_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    for item in sorted(source.rglob("*"), key=lambda path: path.as_posix()):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise kitpro_repo.PipelineError(f"generation contains symlink: {relative}")
        if item.is_dir():
            target.mkdir(parents=True, mode=0o700, exist_ok=True)
            continue
        if not item.is_file():
            raise kitpro_repo.PipelineError(f"generation contains unsafe entry: {relative}")
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        shutil.copyfile(item, target)
        os.chmod(target, 0o444)
    for directory in sorted((p for p in destination.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        os.chmod(directory, 0o555)
    os.chmod(destination, 0o555)


def _file_sha(path: Path) -> str:
    if not path.is_file():
        raise kitpro_repo.PipelineError(f"required file is missing: {path}")
    return kitpro_repo.sha256_file(path)


def validate_generation_tree(generation_root: Path) -> dict[str, Any]:
    manifest_path = generation_root / "manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    required = {
        "schema_version",
        "release",
        "generation_id",
        "previous_generation",
        "source",
        "repositories",
        "signing_fingerprints",
        "qualification_ids",
    }
    if set(manifest) != required:
        raise kitpro_repo.PipelineError("production generation manifest fields are invalid")
    if manifest["schema_version"] != 1 or manifest["release"] != RELEASE:
        raise kitpro_repo.PipelineError("production generation manifest has wrong release")
    generation = manifest["generation_id"]
    generation_number(generation)
    repositories = manifest["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise kitpro_repo.PipelineError("production generation must contain exactly one repository")
    repository = repositories[0]
    database = repository.get("database", {})
    package_records = repository.get("packages", [])
    repo_dir = generation_root / "core/os/x86_64"
    db_path = repo_dir / database.get("filename", "")
    db_sig_path = repo_dir / database.get("signature_filename", "")
    if _file_sha(db_path) != database.get("sha256"):
        raise kitpro_repo.PipelineError("repository database hash mismatch")
    if _file_sha(db_sig_path) != database.get("signature_sha256"):
        raise kitpro_repo.PipelineError("repository database signature hash mismatch")
    if database.get("signer_fingerprint") != manifest["signing_fingerprints"].get("repository"):
        raise kitpro_repo.PipelineError("repository database signer differs from manifest")
    for package in package_records:
        package_path = repo_dir / package["filename"]
        signature_path = repo_dir / package["signature_filename"]
        if _file_sha(package_path) != package["sha256"]:
            raise kitpro_repo.PipelineError(f"package hash mismatch: {package['filename']}")
        if _file_sha(signature_path) != package["signature_sha256"]:
            raise kitpro_repo.PipelineError(f"package signature hash mismatch: {package['signature_filename']}")
        if package["signer_fingerprint"] != manifest["signing_fingerprints"].get("package"):
            raise kitpro_repo.PipelineError(f"package signer differs: {package['filename']}")
    findings = contamination_findings(generation_root)
    if findings:
        raise kitpro_repo.PipelineError(f"production generation contains development contamination: {findings}")
    return {
        "status": "passed",
        "release": RELEASE,
        "generation": generation,
        "previous_generation": manifest["previous_generation"],
        "generation_manifest_sha256": kitpro_repo.sha256_file(manifest_path),
        "repository_db_sha256": database["sha256"],
        "repository_db_signature_sha256": database["signature_sha256"],
        "package_count": len(package_records),
        "signing_fingerprints": manifest["signing_fingerprints"],
    }


def current_generation(public_root: Path) -> str | None:
    current = public_root / "stable" / RELEASE / "current"
    if not current.exists():
        return None
    if not current.is_symlink():
        raise kitpro_repo.PipelineError("current pointer is not a symlink")
    target = os.readlink(current)
    generation = Path(target).name
    generation_number(generation)
    return generation


def publish_generation(
    source_generation: Path,
    public_root: Path,
    *,
    publisher_identity: str = "dry-run-publisher",
    publication_host_identity: str = "dry-run-public-origin",
) -> dict[str, Any]:
    validation = validate_generation_tree(source_generation)
    generation = validation["generation"]
    previous = current_generation(public_root)
    if previous is not None and generation_number(generation) <= generation_number(previous):
        raise kitpro_repo.PipelineError("refusing to move production current backward or sideways")
    final = public_root / "stable" / RELEASE / generation
    if final.exists():
        raise kitpro_repo.PipelineError(f"production generation already exists: {generation}")
    final.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{generation}.", dir=final.parent))
    try:
        staged_generation = staging / generation
        _copy_immutable_tree(source_generation, staged_generation)
        validate_generation_tree(staged_generation)
        os.chmod(staged_generation, 0o755)
        os.replace(staged_generation, final)
        os.chmod(final, 0o555)
    finally:
        if staging.exists():
            for path in sorted(staging.rglob("*"), key=lambda p: len(p.parts), reverse=True):
                if path.is_dir() and not path.is_symlink():
                    os.chmod(path, 0o700)
            shutil.rmtree(staging, ignore_errors=True)
    current = public_root / "stable" / RELEASE / "current"
    temporary = current.with_name(".current.next")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(generation)
    os.replace(temporary, current)
    receipt = {
        "schema_version": 1,
        "timestamp": kitpro_repo.utc_now(),
        "release": RELEASE,
        "previous_generation": previous,
        "new_generation": generation,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "repository_db_sha256": validation["repository_db_sha256"],
        "repository_db_signature_sha256": validation["repository_db_signature_sha256"],
        "pointer_update_method": "atomic-symlink-replace",
        "validation_result": "passed",
        "publisher_identity": publisher_identity,
        "signing_fingerprints": validation["signing_fingerprints"],
        "publication_host_identity": publication_host_identity,
    }
    receipt_dir = public_root / "publication-receipts" / RELEASE
    receipt_dir.mkdir(parents=True, mode=0o755, exist_ok=True)
    receipt_path = receipt_dir / f"{generation}.json"
    kitpro_repo.atomic_write_json(receipt_path, receipt)
    os.chmod(receipt_path, 0o444)
    return {
        "status": "passed",
        "generation": generation,
        "previous_generation": previous,
        "current": current_generation(public_root),
        "receipt": str(receipt_path),
        "receipt_sha256": kitpro_repo.sha256_file(receipt_path),
    }


def restore_from_backup(backup_root: Path, restored_root: Path) -> dict[str, Any]:
    if restored_root.exists():
        raise kitpro_repo.PipelineError("restore destination already exists")
    shutil.copytree(backup_root, restored_root, symlinks=True)
    current = current_generation(restored_root)
    if current is None:
        raise kitpro_repo.PipelineError("restored repository has no current pointer")
    receipt = restored_root / "publication-receipts" / RELEASE / f"{current}.json"
    if not receipt.is_file():
        raise kitpro_repo.PipelineError("restored repository is missing current publication receipt")
    target = restored_root / "stable" / RELEASE / current
    validation = validate_generation_tree(target)
    if kitpro_repo.sha256_file(target / "manifest.json") != kitpro_repo.load_json(receipt)["generation_manifest_sha256"]:
        raise kitpro_repo.PipelineError("restored current does not match receipt")
    return {
        "status": "passed",
        "current": current,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "receipt_sha256": kitpro_repo.sha256_file(receipt),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("client-config")
    validate = subcommands.add_parser("validate-generation")
    validate.add_argument("generation", type=Path)
    publish = subcommands.add_parser("publish")
    publish.add_argument("generation", type=Path)
    publish.add_argument("public_root", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "client-config":
        print(production_pacman_config(), end="")
        return 0
    if arguments.command == "validate-generation":
        print(json.dumps(validate_generation_tree(arguments.generation), indent=2, sort_keys=True))
        return 0
    if arguments.command == "publish":
        print(json.dumps(publish_generation(arguments.generation, arguments.public_root), indent=2, sort_keys=True))
        return 0
    raise AssertionError(arguments.command)


if __name__ == "__main__":
    raise SystemExit(main())
