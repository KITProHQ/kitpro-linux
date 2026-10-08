#!/usr/bin/env python3
"""Publish verified immutable generations; advance current in a separate step.

Standalone so the repository origin needs only Python's standard library.
The operator supplies the manifest hash already verified on the build worker.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate(root: Path, expected_manifest: str) -> dict:
    manifest_path = root / "manifest.json"
    if digest(manifest_path) != expected_manifest:
        raise ValueError("publication manifest hash differs from approved source")
    m = json.loads(manifest_path.read_text())
    if (m["release"] != "1.0" or m["generation_id"] not in ("1.0-g0001", "1.0-g0002")
            or m["qualification_state"] != "signed-awaiting-client-qualification"
            or m["package_count"] != 199 or m["explicit_package_count"] != 36):
        raise ValueError("generation has not passed signed construction validation")
    expected = {"manifest.json": expected_manifest}
    prefix = "core/os/x86_64/"
    for p in m["packages"]:
        for field in ("filename", "signature_filename"):
            if Path(p[field]).name != p[field]:
                raise ValueError("unsafe manifest path")
        expected[prefix + p["filename"]] = p["sha256"]
        expected[prefix + p["signature_filename"]] = p["signature_sha256"]
    db = m["database"]
    for name in ("kitpro-1.0-core.db", "kitpro-1.0-core.db.tar.gz"):
        expected[prefix + name] = db["sha256"]
        expected[prefix + name + ".sig"] = db["signature_sha256"]
    found = set()
    for p in root.rglob("*"):
        if p.is_symlink():
            raise ValueError("publication tree contains symlink")
        if p.is_dir():
            continue
        relative = p.relative_to(root).as_posix()
        if not p.is_file() or p.stat().st_nlink != 1 or relative not in expected:
            raise ValueError("publication tree contains unexpected entry")
        if digest(p) != expected[relative]:
            raise ValueError(f"publication artifact hash mismatch: {relative}")
        found.add(relative)
    if found != set(expected):
        raise ValueError("publication tree is incomplete")
    artifact_inventory = [{"path": name, "sha256": expected[name]}
                          for name in sorted(expected) if name != "manifest.json"]
    canonical = (json.dumps(artifact_inventory, indent=2, sort_keys=True) + "\n").encode()
    if hashlib.sha256(canonical).hexdigest() != m["artifact_set_sha256"]:
        raise ValueError("artifact-set hash mismatch")
    return m


def receipt(root: Path, name: str, value: dict) -> dict:
    target = root / "publication-receipts/1.0" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    value["timestamp"] = datetime.now(timezone.utc).isoformat()
    value["publication_host"] = "repo.kitpro.us"
    with target.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    target.chmod(0o444)
    return value


def publish(source: Path, public_root: Path, expected_manifest: str) -> dict:
    m = validate(source, expected_manifest)
    parent = public_root / "stable/1.0"
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / m["generation_id"]
    if destination.exists() or destination.is_symlink():
        raise ValueError("immutable generation already exists; refusing replacement")
    # Keep incomplete bytes outside the web content root, on the same filesystem.
    staging = Path(tempfile.mkdtemp(prefix=".kitpro-linux-publication-", dir=public_root.parents[1]))
    staged = staging / m["generation_id"]
    shutil.copytree(source, staged, symlinks=True)
    validate(staged, expected_manifest)
    for p in staged.rglob("*"):
        if p.is_file():
            p.chmod(0o444)
    for p in sorted(staged.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if p.is_dir():
            p.chmod(0o555)
    # Origin actions are serialized by the fixed release publication lock.
    os.rename(staged, destination)
    destination.chmod(0o555)
    staging.rmdir()
    return receipt(public_root, m["generation_id"] + "-published.json", {
        "operation": "publish-immutable", "generation": m["generation_id"],
        "manifest_sha256": expected_manifest, "artifact_set_sha256": m["artifact_set_sha256"],
        "current_changed": False, "result": "passed",
    })


def advance(public_root: Path, generation: str, expected_previous: str,
            manifest_sha: str, verification_path: Path) -> dict:
    parent = public_root / "stable/1.0"
    m = validate(parent / generation, manifest_sha)
    verification = json.loads(verification_path.read_text())
    if (verification.get("status") != "passed" or verification.get("generation") != generation
            or verification.get("manifest_sha256") != manifest_sha
            or verification.get("artifact_set_sha256") != m["artifact_set_sha256"]):
        raise ValueError("matching public immutable verification receipt is required")
    current = parent / "current"
    previous = os.readlink(current) if current.is_symlink() else None
    if current.exists() and previous is None:
        raise ValueError("current must be a relative generation symlink")
    if previous != (None if expected_previous == "none" else expected_previous):
        raise ValueError("current changed since qualification planning")
    if previous != m["predecessor"] or (previous is not None and generation <= previous):
        raise ValueError("current transition must match predecessor and move forward")
    temporary = parent / ".current-next"
    temporary.symlink_to(generation)
    os.replace(temporary, current)
    return receipt(public_root, generation + "-current.json", {
        "operation": "advance-current", "previous_generation": previous,
        "generation": generation, "manifest_sha256": manifest_sha,
        "public_verification_sha256": digest(verification_path),
        "pointer_update_method": "atomic-symlink-replace", "result": "passed",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("publish", "advance"))
    parser.add_argument("--public-root", type=Path, default=Path("/srv/kitpro-repository/kitpro-linux"))
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--generation", choices=("1.0-g0001", "1.0-g0002"))
    parser.add_argument("--expected-previous", choices=("none", "1.0-g0001"))
    parser.add_argument("--public-verification", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256):
        raise ValueError("invalid manifest SHA-256")
    args.public_root.mkdir(parents=True, exist_ok=True)
    with (args.public_root / ".production-publication.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = publish(args.source, args.public_root, args.manifest_sha256) if args.command == "publish" else advance(
            args.public_root, args.generation, args.expected_previous, args.manifest_sha256, args.public_verification)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
