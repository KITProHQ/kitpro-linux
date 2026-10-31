#!/usr/bin/env python3
"""Build and validate manifest-bound repository generation descriptors."""

from __future__ import annotations

import base64
import gzip
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from tools import kitpro_repo


DESCRIPTOR_NAME = "kitpro-generation.json"
DESCRIPTOR_PATTERN = re.compile(r"kitpro-linux-release-[^/]+/kitpro-generation\.json")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def inventory_sha256(packages: list[dict[str, Any]]) -> str:
    """Return the canonical signing-payload inventory identity."""
    return kitpro_repo.sha256_bytes(
        (json.dumps(packages, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )


def descriptor_member(release_package_version: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:-]*", release_package_version):
        raise kitpro_repo.PipelineError("release package version is unsafe")
    return f"kitpro-linux-release-{release_package_version}/{DESCRIPTOR_NAME}"


def descriptor_from_signing_payload(
    payload: dict[str, Any], *, payload_sha256: str
) -> tuple[str, dict[str, Any]]:
    if not SHA256_PATTERN.fullmatch(payload_sha256):
        raise kitpro_repo.PipelineError("signing payload SHA-256 is invalid")
    release = payload.get("release", {})
    construction = payload.get("database_construction", {})
    evidence = payload.get("evidence", {})
    packages = payload.get("core", {}).get("packages", [])
    if (
        payload.get("kind") != "kitpro-linux-production-signing-payload"
        or release.get("canonical_version") != "1.1.0"
        or release.get("generation") != "1.1-g0001"
        or release.get("repository") != "kitpro-1.1-core"
        or release.get("destination") != "stable/1.1/1.1-g0001"
        or construction.get("repository") != release.get("repository")
        or construction.get("package_inventory_sha256") != inventory_sha256(packages)
        or len(packages) != 199
        or sum(item.get("explicit") is True for item in packages) != 36
        or not SHA256_PATTERN.fullmatch(evidence.get("generation_input_sha256", ""))
    ):
        raise kitpro_repo.PipelineError("signing payload generation contract is invalid")
    release_records = [item for item in packages if item.get("name") == "kitpro-linux-release"]
    if len(release_records) != 1 or release_records[0].get("version") != "1.1.0-5":
        raise kitpro_repo.PipelineError("release package generation binding is invalid")
    descriptor = {
        "schema_version": 1,
        "release": "1.1",
        "generation_id": release["generation"],
        "repository": release["repository"],
        "generation_manifest_sha256": evidence["generation_input_sha256"],
        "signing_payload_sha256": payload_sha256,
        "inventory_sha256": construction["package_inventory_sha256"],
        "package_count": len(packages),
        "explicit_package_count": sum(item["explicit"] is True for item in packages),
        "packages": [
            {
                "name": item["name"],
                "version": item["version"],
                "explicit": item["explicit"],
            }
            for item in packages
        ],
    }
    return descriptor_member(release_records[0]["version"]), descriptor


def _normalized_member(member: tarfile.TarInfo, *, source_epoch: int) -> tarfile.TarInfo:
    normalized = tarfile.TarInfo(member.name)
    normalized.type = member.type
    normalized.size = member.size if member.isfile() else 0
    normalized.mode = 0o644 if member.isfile() else 0o755
    normalized.mtime = source_epoch
    normalized.uid = 0
    normalized.gid = 0
    normalized.uname = "root"
    normalized.gname = "root"
    return normalized


def embed_descriptor(
    database: Path,
    *,
    member_name: str,
    descriptor: dict[str, Any],
    source_epoch: int,
) -> None:
    """Add exactly one descriptor while normalizing archive metadata."""
    if not DESCRIPTOR_PATTERN.fullmatch(member_name):
        raise kitpro_repo.PipelineError("generation descriptor member path is invalid")
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    try:
        with tarfile.open(database, "r:gz") as source:
            for member in source.getmembers():
                if DESCRIPTOR_PATTERN.fullmatch(member.name):
                    raise kitpro_repo.PipelineError(
                        "repository database already contains a generation descriptor"
                    )
                if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                    raise kitpro_repo.PipelineError("repository database contains unsafe members")
                data = None
                if member.isfile():
                    extracted = source.extractfile(member)
                    if extracted is None:
                        raise kitpro_repo.PipelineError("repository database member is unreadable")
                    data = extracted.read()
                entries.append((member, data))
    except (tarfile.TarError, OSError) as error:
        raise kitpro_repo.PipelineError("repository database archive is invalid") from error
    descriptor_data = kitpro_repo.canonical_json_bytes(descriptor)
    descriptor_info = tarfile.TarInfo(member_name)
    descriptor_info.type = tarfile.REGTYPE
    descriptor_info.size = len(descriptor_data)
    entries.append((descriptor_info, descriptor_data))
    temporary = database.with_name(f".{database.name}.with-generation")
    try:
        with (
            temporary.open("wb") as output,
            gzip.GzipFile(
                filename="",
                fileobj=output,
                mode="wb",
                compresslevel=9,
                mtime=source_epoch,
            ) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as destination,
        ):
            for member, data in sorted(entries, key=lambda item: item[0].name):
                normalized = _normalized_member(member, source_epoch=source_epoch)
                destination.addfile(normalized, io.BytesIO(data) if data is not None else None)
        temporary.replace(database)
    finally:
        temporary.unlink(missing_ok=True)


def _fields(data: bytes) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    try:
        text = data.decode()
    except UnicodeDecodeError as error:
        raise kitpro_repo.PipelineError("repository description is not UTF-8") from error
    for section in text.strip().split("\n\n"):
        lines = section.splitlines()
        if lines and lines[0].startswith("%") and lines[0].endswith("%"):
            fields[lines[0].strip("%")] = lines[1:]
    return fields


def validate_database(
    database: Path,
    *,
    expected_member: str,
    expected_descriptor: dict[str, Any],
    packages: list[dict[str, Any]],
    package_directory: Path | None = None,
) -> dict[str, Any]:
    """Validate archive shape, semantic identity, inventory, hashes, and signatures."""
    expected_names = {item["name"] for item in packages}
    if len(expected_names) != len(packages):
        raise kitpro_repo.PipelineError("approved package inventory contains duplicates")
    descriptor_members: list[tarfile.TarInfo] = []
    descriptions: dict[str, tuple[tarfile.TarInfo, dict[str, list[str]]]] = {}
    directories: set[str] = set()
    try:
        with tarfile.open(database, "r:gz") as archive:
            for member in archive.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or len(path.parts) not in (1, 2):
                    raise kitpro_repo.PipelineError("repository database contains unsafe members")
                if DESCRIPTOR_PATTERN.fullmatch(member.name):
                    descriptor_members.append(member)
                    continue
                if member.isdir() and len(path.parts) == 1:
                    directories.add(member.name)
                    continue
                if not member.isfile() or len(path.parts) != 2 or path.name != "desc":
                    raise kitpro_repo.PipelineError(
                        "repository database contains unsupported members"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise kitpro_repo.PipelineError("repository description is unreadable")
                fields = _fields(extracted.read())
                names = fields.get("NAME", [])
                if len(names) != 1 or names[0] in descriptions:
                    raise kitpro_repo.PipelineError("repository package identity is ambiguous")
                descriptions[names[0]] = (member, fields)
            if (
                len(descriptor_members) != 1
                or descriptor_members[0].name != expected_member
                or not descriptor_members[0].isfile()
                or descriptor_members[0].size > 262144
            ):
                raise kitpro_repo.PipelineError(
                    "repository database must contain exactly one expected generation descriptor"
                )
            extracted = archive.extractfile(descriptor_members[0])
            if extracted is None:
                raise kitpro_repo.PipelineError("generation descriptor is unreadable")
            try:
                observed_descriptor = json.load(extracted)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise kitpro_repo.PipelineError("generation descriptor is malformed") from error
    except (tarfile.TarError, OSError) as error:
        raise kitpro_repo.PipelineError("repository database archive is invalid") from error
    if observed_descriptor != expected_descriptor:
        raise kitpro_repo.PipelineError("generation descriptor differs from approved contract")
    if set(descriptions) != expected_names:
        raise kitpro_repo.PipelineError(
            "repository database inventory differs from approved inventory"
        )
    expected_directories = {member.name.rsplit("/", 1)[0] for member, _ in descriptions.values()}
    if directories != expected_directories or expected_member.rsplit("/", 1)[0] not in directories:
        raise kitpro_repo.PipelineError("repository database directory layout is inconsistent")
    for package in packages:
        _, fields = descriptions[package["name"]]
        expected = {
            "VERSION": package["version"],
            "FILENAME": package["filename"],
            "SHA256SUM": package["sha256"],
        }
        for field, value in expected.items():
            if fields.get(field) != [value]:
                raise kitpro_repo.PipelineError(
                    f"repository database {field.lower()} differs: {package['name']}"
                )
        signatures = fields.get("PGPSIG", [])
        if len(signatures) != 1:
            raise kitpro_repo.PipelineError(
                f"repository database package signature is missing: {package['name']}"
            )
        if package_directory is not None:
            artifact = package_directory / package["filename"]
            signature = package_directory / package["signature_filename"]
            if (
                not artifact.is_file()
                or artifact.is_symlink()
                or kitpro_repo.sha256_file(artifact) != package["sha256"]
                or not signature.is_file()
                or signature.is_symlink()
                or kitpro_repo.sha256_file(signature) != package["signature_sha256"]
            ):
                raise kitpro_repo.PipelineError(
                    f"repository package or signature bytes differ: {package['name']}"
                )
            try:
                embedded = base64.b64decode(signatures[0], validate=True)
            except ValueError as error:
                raise kitpro_repo.PipelineError(
                    "repository package signature is malformed"
                ) from error
            if embedded != signature.read_bytes():
                raise kitpro_repo.PipelineError(
                    f"repository embedded package signature differs: {package['name']}"
                )
    return {
        "status": "passed",
        "descriptor_member": expected_member,
        "descriptor_sha256": kitpro_repo.sha256_bytes(
            kitpro_repo.canonical_json_bytes(observed_descriptor)
        ),
        "package_count": len(packages),
        "explicit_package_count": sum(item["explicit"] is True for item in packages),
        "inventory_sha256": expected_descriptor["inventory_sha256"],
    }


def validate_signed_database(
    database: Path,
    signature: Path,
    *,
    public_home: Path,
    expected_signer: str,
    expected_member: str,
    expected_descriptor: dict[str, Any],
    packages: list[dict[str, Any]],
    package_directory: Path | None = None,
) -> dict[str, Any]:
    """Require both valid cryptography and valid generation semantics."""
    signer = kitpro_repo.verify_signature(public_home, signature, database)
    if signer != expected_signer:
        raise kitpro_repo.PipelineError("repository database signer differs")
    result = validate_database(
        database,
        expected_member=expected_member,
        expected_descriptor=expected_descriptor,
        packages=packages,
        package_directory=package_directory,
    )
    return {**result, "signer_fingerprint": signer}


def package_names(packages: Iterable[dict[str, Any]]) -> set[str]:
    return {item["name"] for item in packages}
