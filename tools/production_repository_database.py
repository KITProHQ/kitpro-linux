#!/usr/bin/env python3
"""Construct and qualify a descriptor-bound Linux 1.1 repository database."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from tools import generation_descriptor, kitpro_repo


APPROVED_PAYLOAD_SHA256 = "9881e96f6c2f824c1dc7b115a5172385e0a394d5e06e921f7403b0452b72770d"
APPROVED_INVENTORY_SHA256 = "864d486f6708c3d76fec753693a7102c0d868c18946445286e941dcac799109b"
RELEASE_PACKAGE_SHA256 = "cf3eb320774fd2f7d2cdd491ed4f714d758fdd9cbd4cdd398bc0ecaecd344785"
RELEASE_PACKAGE_SIGNATURE_SHA256 = (
    "9c01a7fbdb075835a84077ea7bb3ed91fcd5593e8a100c857c7f68adde497aa5"
)
PACKAGE_FINGERPRINT = "4742B8D5550858F1723C8E0DB0DCE551DDD9F456"
REPOSITORY_FINGERPRINT = "52BADA3613798054B7E35840DC088D21DA29F538"
SOURCE_EPOCH = 1793401705
REPOSITORY_NAME = "kitpro-1.1-core"
FORBIDDEN_CORE = {"kitpro-server", "docker", "containerd", "runc"}


def _public_home(path: Path, key_data: bytes) -> Path:
    path.mkdir(parents=True, mode=0o700)
    os.chmod(path, 0o700)
    kitpro_repo.gpg_import(path, key_data)
    return path


def final_package_records(
    payload: dict[str, Any], ceremony: dict[str, Any]
) -> list[dict[str, Any]]:
    records = [dict(item) for item in payload["core"]["packages"]]
    release = [item for item in records if item.get("name") == "kitpro-linux-release"]
    if len(release) != 1:
        raise kitpro_repo.PipelineError("approved inventory release package is ambiguous")
    release[0].update(
        {
            "signature_filename": f"{release[0]['filename']}.sig",
            "signature_sha256": RELEASE_PACKAGE_SIGNATURE_SHA256,
            "signer_fingerprint": PACKAGE_FINGERPRINT,
            "origin": "kitpro-production",
        }
    )
    if (
        len(records) != 199
        or sum(item.get("explicit") is True for item in records) != 36
        or generation_descriptor.inventory_sha256(payload["core"]["packages"])
        != APPROVED_INVENTORY_SHA256
        or {item["name"] for item in records} & FORBIDDEN_CORE
        or ceremony.get("package", {}).get("sha256") != RELEASE_PACKAGE_SHA256
        or ceremony.get("package", {}).get("signature_sha256") != RELEASE_PACKAGE_SIGNATURE_SHA256
    ):
        raise kitpro_repo.PipelineError("approved production package closure differs")
    return sorted(records, key=lambda item: item["name"])


def verify_package_inputs(
    package_directory: Path,
    records: list[dict[str, Any]],
    public_root: Path,
) -> dict[str, int]:
    keyring_package = package_directory / "kitpro-linux-keyring-1.0-1-any.pkg.tar.zst"
    kitpro_keyring = kitpro_repo.package_member(
        keyring_package, "usr/share/pacman/keyrings/kitpro-linux.gpg"
    )
    arch_keyring_package = package_directory / "archlinux-keyring-20260909-1-any.pkg.tar.zst"
    arch_keyring = kitpro_repo.package_member(
        arch_keyring_package, "usr/share/pacman/keyrings/archlinux.gpg"
    )
    kitpro_home = _public_home(public_root / "kitpro-home", kitpro_keyring)
    arch_home = _public_home(public_root / "arch-home", arch_keyring)
    counts = {"arch": 0, "kitpro": 0}
    for record in records:
        artifact = package_directory / record["filename"]
        signature = package_directory / record["signature_filename"]
        if (
            not artifact.is_file()
            or artifact.is_symlink()
            or kitpro_repo.sha256_file(artifact) != record["sha256"]
            or not signature.is_file()
            or signature.is_symlink()
            or kitpro_repo.sha256_file(signature) != record["signature_sha256"]
        ):
            raise kitpro_repo.PipelineError(
                f"approved package or signature bytes differ: {record['name']}"
            )
        role = "kitpro" if record["name"].startswith("kitpro-") else "arch"
        home = kitpro_home if role == "kitpro" else arch_home
        signer = kitpro_repo.verify_signature(home, signature, artifact)
        if signer != record["signer_fingerprint"]:
            raise kitpro_repo.PipelineError(f"package signer differs: {record['name']}")
        counts[role] += 1
    return counts


def validate_pacman_read(database: Path, expected_names: set[str]) -> None:
    with tempfile.TemporaryDirectory(prefix="kitpro-corrected-db-pacman-") as temporary:
        root = Path(temporary)
        sync = root / "db/sync"
        sync.mkdir(parents=True)
        shutil.copyfile(database, sync / f"{REPOSITORY_NAME}.db")
        config = root / "pacman.conf"
        config.write_text(
            f"[options]\nSigLevel = Never\n[{REPOSITORY_NAME}]\nServer = file:///nonexistent\n"
        )
        result = subprocess.run(
            [
                "pacman",
                "--config",
                str(config),
                "--dbpath",
                str(root / "db"),
                "-Slq",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        observed = result.stdout.splitlines()
        if (
            result.stderr.strip()
            or len(observed) != len(expected_names)
            or set(observed) != expected_names
        ):
            raise kitpro_repo.PipelineError("pacman rejected corrected database inventory")


def _signed_semantic_negative_control(
    database: Path,
    *,
    output_root: Path,
    key_state: Path,
    fingerprint: str,
    member: str,
    descriptor: dict[str, Any],
    records: list[dict[str, Any]],
    package_directory: Path,
) -> bool:
    negative = output_root / "negative-signed-wrong-generation.db.tar.gz"
    wrong = dict(descriptor)
    wrong["generation_id"] = "1.1-g0002"
    with tarfile.open(database, "r:gz") as source, tarfile.open(negative, "w:gz") as target:
        for entry in source.getmembers():
            if entry.name == member:
                data = kitpro_repo.canonical_json_bytes(wrong)
                replacement = tarfile.TarInfo(entry.name)
                replacement.size = len(data)
                replacement.mode = 0o644
                target.addfile(replacement, io.BytesIO(data))
            else:
                target.addfile(entry, source.extractfile(entry) if entry.isfile() else None)
    signature = negative.with_name(f"{negative.name}.sig")
    kitpro_repo.detached_sign(key_state / "repository", fingerprint, negative, signature)
    try:
        generation_descriptor.validate_signed_database(
            negative,
            signature,
            public_home=key_state / "repository",
            expected_signer=fingerprint,
            expected_member=member,
            expected_descriptor=descriptor,
            packages=records,
            package_directory=package_directory,
        )
    except kitpro_repo.PipelineError as error:
        if "approved contract" not in str(error):
            raise
        return True
    raise kitpro_repo.PipelineError("signed semantically invalid database was accepted")


def build(
    *,
    package_directory: Path,
    payload_path: Path,
    ceremony_path: Path,
    output_root: Path,
    source_commit: str,
    source_tree: str,
    test_key_state: Path | None = None,
) -> dict[str, Any]:
    if output_root.exists():
        raise kitpro_repo.PipelineError(f"refusing to replace output: {output_root}")
    if kitpro_repo.sha256_file(payload_path) != APPROVED_PAYLOAD_SHA256:
        raise kitpro_repo.PipelineError("approved signing payload changed")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit) or not re.fullmatch(
        r"[0-9a-f]{40}", source_tree
    ):
        raise kitpro_repo.PipelineError("repository builder source identity is invalid")
    payload = kitpro_repo.load_json(payload_path)
    ceremony = kitpro_repo.load_json(ceremony_path)
    records = final_package_records(payload, ceremony)
    output_root.mkdir(parents=True)
    verification = verify_package_inputs(
        package_directory, records, output_root / "public-only-keyrings"
    )
    database = output_root / f"{REPOSITORY_NAME}.db.tar.gz"
    package_files = [package_directory / record["filename"] for record in records]
    kitpro_repo.run(
        ["repo-add", "--include-sigs", str(database), *[str(path) for path in package_files]]
    )
    files_database = output_root / f"{REPOSITORY_NAME}.files.tar.gz"
    files_database.unlink(missing_ok=True)
    for alias in (output_root / REPOSITORY_NAME, output_root / f"{REPOSITORY_NAME}.db"):
        alias.unlink(missing_ok=True)
    kitpro_repo.normalize_tar_gz(database, SOURCE_EPOCH)
    member, descriptor = generation_descriptor.descriptor_from_signing_payload(
        payload, payload_sha256=APPROVED_PAYLOAD_SHA256
    )
    generation_descriptor.embed_descriptor(
        database,
        member_name=member,
        descriptor=descriptor,
        source_epoch=SOURCE_EPOCH,
    )
    semantic = generation_descriptor.validate_database(
        database,
        expected_member=member,
        expected_descriptor=descriptor,
        packages=records,
        package_directory=package_directory,
    )
    validate_pacman_read(database, {record["name"] for record in records})
    test_signature: dict[str, Any] | None = None
    if test_key_state is not None:
        key_manifest = kitpro_repo.load_json(test_key_state / "keys.json")
        if key_manifest.get("development_only") is not True:
            raise kitpro_repo.PipelineError("test Repository key is not development-only")
        repository = key_manifest["roles"]["repository"]
        fingerprint = repository["fingerprint"]
        if fingerprint == REPOSITORY_FINGERPRINT or "DEVELOPMENT" not in repository["uid"]:
            raise kitpro_repo.PipelineError("test Repository key overlaps production trust")
        signature = database.with_name(f"{database.name}.test.sig")
        kitpro_repo.detached_sign(test_key_state / "repository", fingerprint, database, signature)
        signed_semantic = generation_descriptor.validate_signed_database(
            database,
            signature,
            public_home=test_key_state / "repository",
            expected_signer=fingerprint,
            expected_member=member,
            expected_descriptor=descriptor,
            packages=records,
            package_directory=package_directory,
        )
        signed_invalid_rejected = _signed_semantic_negative_control(
            database,
            output_root=output_root,
            key_state=test_key_state,
            fingerprint=fingerprint,
            member=member,
            descriptor=descriptor,
            records=records,
            package_directory=package_directory,
        )
        test_signature = {
            "filename": signature.name,
            "sha256": kitpro_repo.sha256_file(signature),
            "fingerprint": fingerprint,
            "development_only": True,
            "semantic_validation": signed_semantic,
            "signed_semantically_invalid_database_rejected": signed_invalid_rejected,
        }
    approval = {
        "schema_version": 1,
        "kind": "kitpro-linux-repository-resigning-approval-packet",
        "status": "go-for-owner-authorized-repository-resigning-only",
        "release": "1.1.0",
        "generation": "1.1-g0001",
        "repository": REPOSITORY_NAME,
        "repository_builder_source": {
            "commit": source_commit,
            "tree": source_tree,
        },
        "approved_signing_payload_sha256": APPROVED_PAYLOAD_SHA256,
        "approved_inventory_sha256": APPROVED_INVENTORY_SHA256,
        "package_count": 199,
        "explicit_package_count": 36,
        "database": {
            "filename": database.name,
            "sha256": kitpro_repo.sha256_file(database),
            "descriptor_member": member,
            "descriptor_sha256": semantic["descriptor_sha256"],
        },
        "unchanged_release_package": {
            "filename": "kitpro-linux-release-1.1.0-5-any.pkg.tar.zst",
            "sha256": RELEASE_PACKAGE_SHA256,
            "signature_sha256": RELEASE_PACKAGE_SIGNATURE_SHA256,
            "package_signer": PACKAGE_FINGERPRINT,
        },
        "required_repository_signer": REPOSITORY_FINGERPRINT,
        "package_signature_verification": verification,
        "test_repository_signature": test_signature,
        "semantic_validation": semantic,
        "production_repository_signature_present": False,
        "production_signing_authorized": False,
        "publication_authorized": False,
    }
    approval_path = output_root / "repository-resigning-approval-packet.json"
    kitpro_repo.atomic_write_json(approval_path, approval)
    return {
        **approval,
        "approval_packet_sha256": kitpro_repo.sha256_file(approval_path),
        "approval_packet_path": str(approval_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-directory", type=Path, required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--ceremony", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--test-key-state", type=Path)
    arguments = parser.parse_args()
    result = build(
        package_directory=arguments.package_directory.resolve(),
        payload_path=arguments.payload.resolve(),
        ceremony_path=arguments.ceremony.resolve(),
        output_root=arguments.output.resolve(),
        source_commit=arguments.source_commit,
        source_tree=arguments.source_tree,
        test_key_state=(arguments.test_key_state.resolve() if arguments.test_key_state else None),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
