#!/usr/bin/env python3
"""Construct production generations from frozen bytes and detached signatures.

This tool has no signing, publication, or current-pointer operation. The DB
must be externally signed and finalized before it can pass validation.
"""
from __future__ import annotations

import argparse
import base64
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from tools import kitpro_repo
from tools.production_identity import MEMBER, descriptor
from tools.production_packages import FINGERPRINTS
from tools.production_repository import PRODUCTION_BASE_URL, production_pacman_config, private_infrastructure_markers

BASELINE_SHA256 = "d1c9ace9b6f0f6027acd6d5bd3624aa8f660cf30e124cd60213b6662eab41da2"
KERNELS = {
    "1.0-g0001": ("6.18.54-1", "357b5695c0a97253ba3472ba99cd56b113f20d87c84d77c13dfba86980dac8a6", "9af896f1f46a110273bdcfda5fdf0a2dc12e964e63fa4520c0819abea1e2f1e3"),
    "1.0-g0002": ("6.18.55-1", "d7b80550feb4309cd812bb21d0965d6e26f5ec72241c96a7ad57a3eb8b5f7e12", "5c9ea826b8fbe72d32627fa77d183088272d29a45dab5316166d0090142ca934"),
}
NATIVE = {"kitpro-linux-base", "kitpro-linux-keyring", "kitpro-linux-release", "kitpro-linux-repository-trust"}
ADMIN = {"nano", "vim", "bash-completion", "less", "which", "man-db", "man-pages", "rsync", "jq", "bind", "tcpdump", "dmidecode", "smartmontools", "nvme-cli", "strace"}
REPO_NAME = "kitpro-1.0-core"


def checked(path: Path, digest: str) -> Path:
    if not path.is_file() or path.is_symlink() or kitpro_repo.sha256_file(path) != digest:
        raise ValueError(f"artifact missing, unsafe, or hash mismatch: {path.name}")
    return path


def scan_metadata(data: bytes) -> None:
    markers = (b"0.1-dev", b"KITPro Linux TEST", b"DEVELOPMENT", b"/tmp/",
               b"signing-drop", b"kitpro-development-repository-ca",
               b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----",
               b"-----BEGIN PGP " + b"SECRET KEY BLOCK-----",
               b"08EFE9334C7A7D3F2CDC3356F5320620398ED776",
               b"EC2A68DE021986F40177579EF150A7031F2C73E7")
    if private_infrastructure_markers(data.decode(errors="ignore")) or any(marker in data for marker in markers):
        raise ValueError("production metadata contains forbidden contamination")


def db_inventory(path: Path) -> dict[str, dict]:
    records = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.name.endswith("/desc"):
                continue
            text = archive.extractfile(member).read().decode()
            fields = {}
            for section in text.strip().split("\n\n"):
                lines = section.splitlines()
                if lines and lines[0].startswith("%"):
                    fields[lines[0].strip("%")] = lines[1:]
            name = fields["NAME"][0]
            if name in records:
                raise ValueError("duplicate package in production DB")
            records[name] = fields
    return records


def validate_inventory(manifest: dict, directory: Path, public_home: Path,
                       arch_home: Path) -> None:
    packages = manifest["packages"]
    names = {p["name"] for p in packages}
    if len(packages) != 199 or len(names) != 199 or sum(p["explicit"] for p in packages) != 36:
        raise ValueError("frozen production inventory counts differ")
    if not ADMIN <= names or {p["name"] for p in packages if p["name"].startswith("kitpro-")} != NATIVE:
        raise ValueError("frozen administrator/native baseline differs")
    db = db_inventory(directory / f"{REPO_NAME}.db.tar.gz")
    if set(db) != names:
        raise ValueError("DB package inventory differs from manifest")
    for p in packages:
        for name in (p["filename"], p["signature_filename"]):
            if Path(name).name != name:
                raise ValueError("unsafe manifest artifact basename")
        artifact = checked(directory / p["filename"], p["sha256"])
        signature = checked(directory / p["signature_filename"], p["signature_sha256"])
        home = public_home if p["name"] in NATIVE else arch_home
        if p["name"] in NATIVE and p["signer_fingerprint"] != FINGERPRINTS["package"]:
            raise ValueError("native package does not use production Package authority")
        if kitpro_repo.verify_signature(home, signature, artifact) != p["signer_fingerprint"]:
            raise ValueError("package signer mismatch")
        row = db[p["name"]]
        if (row["VERSION"] != [p["version"]] or row["FILENAME"] != [p["filename"]]
                or row["SHA256SUM"] != [p["sha256"]]
                or base64.b64decode(row["PGPSIG"][0], validate=True) != signature.read_bytes()):
            raise ValueError("signed-package metadata differs from DB")
    metadata = descriptor(directory / f"{REPO_NAME}.db.tar.gz")
    if metadata != {k: manifest[k] for k in metadata}:
        raise ValueError("embedded generation descriptor differs from manifest")
    scan_metadata(kitpro_repo.canonical_json_bytes(metadata))


def validate_pacman_format(database: Path, names: set[str]) -> None:
    """Exercise libalpm before requesting a signature; never changes client policy."""
    with tempfile.TemporaryDirectory(prefix="kitpro-db-format-") as temporary:
        root = Path(temporary)
        sync = root / "db/sync"
        sync.mkdir(parents=True)
        shutil.copyfile(database, sync / f"{REPO_NAME}.db")
        config = root / "pacman.conf"
        # The candidate has no DB signature yet. This isolated, offline query
        # checks archive compatibility only; package crypto is checked separately.
        config.write_text(f"[options]\nSigLevel = Never\n[{REPO_NAME}]\nServer = file:///nonexistent\n")
        result = subprocess.run(["pacman", "--config", str(config), "--dbpath", str(root / "db"), "-Slq"],
                                check=True, capture_output=True, text=True)
        observed = result.stdout.splitlines()
        if result.stderr.strip() or len(observed) != len(names) or set(observed) != names:
            raise ValueError("real pacman rejected production DB layout or inventory")


def construct(generation: str, baseline_repo: Path, native: Path, supplemental: Path,
              output: Path, public_home: Path, arch_home: Path, source: dict) -> dict:
    version, kernel_hash, kernel_sig_hash = KERNELS[generation]
    baseline_path = baseline_repo / "stable/0.1-dev/0.1-dev-g0010/manifest.json"
    checked(baseline_path, BASELINE_SHA256)
    baseline = json.loads(baseline_path.read_text())["repositories"][0]["packages"]
    if len(baseline) != 199 or sum(p["explicit"] for p in baseline) != 36:
        raise ValueError("frozen baseline counts differ")
    if output.exists():
        raise ValueError("refusing to replace generation construction output")
    directory = output / "core/os/x86_64"
    directory.mkdir(parents=True)
    records = []
    prepared = json.loads((Path(__file__).resolve().parents[1] / "docs/results/production-generation-preparation.json").read_text())
    approved_native = {p["filename"]: p["sha256"] for p in prepared["packages"]}
    for p in sorted(baseline, key=lambda p: p["name"]):
        name = p["name"]
        if name in NATIVE:
            filename = f"{name}-1.0-1-any.pkg.tar.zst"
            artifact = checked(native / filename, approved_native[filename])
            signature = native / (filename + ".sig")
            signer = FINGERPRINTS["package"]
            package_version = "1.0-1"
            home = public_home
        else:
            digest = kernel_hash if name == "linux-lts" else p["sha256"]
            sig_digest = kernel_sig_hash if name == "linux-lts" else p["upstream_signature"]["sha256"]
            artifact = kitpro_repo.object_path(baseline_repo, digest)
            signature = kitpro_repo.object_path(baseline_repo, sig_digest)
            if not artifact.is_file():
                artifact = supplemental / digest
            if not signature.is_file():
                signature = supplemental / sig_digest
            checked(artifact, digest)
            checked(signature, sig_digest)
            signer = p["upstream_signature"]["signer_fingerprint"]
            package_version = version if name == "linux-lts" else p["version"]
            filename = f"linux-lts-{version}-x86_64.pkg.tar.zst" if name == "linux-lts" else p["filename"]
            home = arch_home
        if kitpro_repo.verify_signature(home, signature, artifact) != signer:
            raise ValueError(f"invalid original/production signature: {name}")
        metadata, _ = kitpro_repo.package_metadata(artifact)
        if kitpro_repo.first(metadata, "pkgname") != name or kitpro_repo.first(metadata, "pkgver") != package_version:
            raise ValueError(f"package metadata mismatch: {name}")
        shutil.copyfile(artifact, directory / filename)
        shutil.copyfile(signature, directory / (filename + ".sig"))
        records.append({"name": name, "version": package_version, "explicit": p["explicit"],
                        "filename": filename, "sha256": kitpro_repo.sha256_file(artifact),
                        "signature_filename": filename + ".sig", "signature_sha256": kitpro_repo.sha256_file(signature),
                        "signer_fingerprint": signer,
                        "origin": "kitpro-production" if name in NATIVE else "arch-original"})
    manifest = {"schema_version": 1, "release": "1.0", "generation_id": generation,
                "predecessor": None if generation == "1.0-g0001" else "1.0-g0001",
                "source": source, "package_count": 199, "explicit_package_count": 36,
                "kernel_version": version, "production_url": f"{PRODUCTION_BASE_URL}/stable/1.0/{generation}/core/os/x86_64",
                "signing_fingerprints": {r: FINGERPRINTS[r] for r in ("root", "package", "repository")},
                "packages": records}
    scan_metadata(kitpro_repo.canonical_json_bytes(manifest))
    database = directory / f"{REPO_NAME}.db.tar.gz"
    subprocess.run(["repo-add", "--include-sigs", str(database),
                    *[str(directory / p["filename"]) for p in records]], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # The descriptor is authenticated by the same detached DB signature as all
    # package records. Put it inside the existing release package directory:
    # libalpm rejects non-package top-level members, but skips extra package files.
    temporary = output / "database-with-identity.tar.gz"
    with tarfile.open(database, "r:gz") as src, tarfile.open(temporary, "w:gz") as dst:
        for member in src.getmembers():
            dst.addfile(member, src.extractfile(member) if member.isfile() else None)
        data = kitpro_repo.canonical_json_bytes(manifest)
        member = tarfile.TarInfo(MEMBER)
        member.size, member.mode, member.mtime = len(data), 0o644, source["epoch"]
        dst.addfile(member, io.BytesIO(data))
    os.replace(temporary, database)
    # Publish ordinary files, never repo-add's filesystem links or unsigned .files.
    for path in directory.iterdir():
        if path.name not in {p["filename"] for p in records} | {p["signature_filename"] for p in records} | {database.name}:
            path.unlink()
    shutil.copyfile(database, directory / f"{REPO_NAME}.db")
    validate_pacman_format(database, {p["name"] for p in records})
    validate_inventory(manifest, directory, public_home, arch_home)
    manifest["database"] = {"filename": database.name, "sha256": kitpro_repo.sha256_file(database),
                            "signature_filename": database.name + ".sig", "signature_sha256": None,
                            "signer_fingerprint": FINGERPRINTS["repository"]}
    manifest["qualification_state"] = "awaiting-repository-signature"
    kitpro_repo.atomic_write_json(output / "manifest.json", manifest)
    return manifest


def finalize(output: Path, signature: Path, public_home: Path, arch_home: Path) -> dict:
    manifest = json.loads((output / "manifest.json").read_text())
    directory = output / "core/os/x86_64"
    database = checked(directory / manifest["database"]["filename"], manifest["database"]["sha256"])
    if kitpro_repo.verify_signature(public_home, signature, database) != FINGERPRINTS["repository"]:
        raise ValueError("DB signer is not the production Repository key")
    validate_inventory(manifest, directory, public_home, arch_home)
    for name in (database.name + ".sig", REPO_NAME + ".db.sig"):
        destination = directory / name
        if destination.exists() and destination.read_bytes() != signature.read_bytes():
            raise ValueError("refusing to replace a different DB signature")
        shutil.copyfile(signature, destination)
    manifest["database"]["signature_sha256"] = kitpro_repo.sha256_file(signature)
    manifest["qualification_state"] = "signed-awaiting-client-qualification"
    inventory = [{"path": p.relative_to(output).as_posix(), "sha256": kitpro_repo.sha256_file(p)}
                 for p in sorted(directory.iterdir())]
    manifest["artifact_set_sha256"] = kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(inventory))
    kitpro_repo.atomic_write_json(output / "manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("construct", "finalize"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-home", type=Path, required=True)
    parser.add_argument("--arch-home", type=Path, required=True)
    parser.add_argument("--generation", choices=tuple(KERNELS))
    parser.add_argument("--baseline-repo", type=Path)
    parser.add_argument("--native", type=Path)
    parser.add_argument("--supplemental", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--signature", type=Path)
    args = parser.parse_args()
    if args.command == "construct":
        result = construct(args.generation, args.baseline_repo, args.native, args.supplemental,
                           args.output, args.public_home, args.arch_home, json.loads(args.source.read_text()))
    else:
        result = finalize(args.output, args.signature, args.public_home, args.arch_home)
    print(json.dumps({k: v for k, v in result.items() if k != "packages"}, indent=2))


if __name__ == "__main__":
    main()
