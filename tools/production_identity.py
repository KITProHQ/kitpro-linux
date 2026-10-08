#!/usr/bin/env python3
"""Record installed generation identity from the signed production sync DB."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

REPOSITORY_FINGERPRINT = "52BADA3613798054B7E35840DC088D21DA29F538"
MEMBER = "kitpro-linux-release-1.0-1/kitpro-generation.json"


def descriptor(database: Path) -> dict:
    with tarfile.open(database, "r:*") as archive:
        entries = [member for member in archive.getmembers() if member.name == MEMBER]
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 262144:
            raise ValueError("production DB generation descriptor is missing or invalid")
        value = json.load(archive.extractfile(entries[0]))
    if (value.get("release") != "1.0" or value.get("schema_version") != 1
            or not re.fullmatch(r"1\.0-g[0-9]{4}", value.get("generation_id", ""))):
        raise ValueError("invalid production generation identity")
    packages = value.get("packages", [])
    if len(packages) != 199 or len({p["name"] for p in packages}) != 199:
        raise ValueError("production inventory must contain 199 distinct packages")
    if sum(p["explicit"] is True for p in packages) != 36:
        raise ValueError("production inventory must contain 36 explicit packages")
    return value


def update(root: Path = Path("/")) -> dict:
    database = root / "var/lib/pacman/sync/kitpro-1.0-core.db"
    verified = subprocess.run(
        ["gpg", "--no-options", "--batch", "--no-auto-key-retrieve", "--no-autostart",
         "--homedir", str(root / "etc/pacman.d/gnupg"), "--status-fd", "1", "--verify",
         str(database) + ".sig", str(database)], check=True, capture_output=True, text=True,
    )
    signatures = [line.split()[2] for line in verified.stdout.splitlines()
                  if line.startswith("[GNUPG:] VALIDSIG ")]
    if signatures != [REPOSITORY_FINGERPRINT]:
        raise ValueError("generation descriptor lacks the exact production Repository signature")
    value = descriptor(database)
    installed = subprocess.run(
        ["pacman", "--root", str(root), "-Q"], check=True, capture_output=True, text=True,
    )
    observed = dict(line.split(maxsplit=1) for line in installed.stdout.splitlines())
    expected = {p["name"]: p["version"] for p in value["packages"]}
    if observed != expected:
        raise ValueError("installed package inventory differs from signed generation")
    destination = root / "etc/kitpro-linux-release.json"
    if destination.exists():
        previous = json.loads(destination.read_text()).get("generation")
        if previous and previous > value["generation_id"]:
            raise ValueError("refusing generation identity rollback")
    release = json.loads((root / "usr/lib/kitpro-linux/release.json").read_text())
    if release.get("release") != "1.0" or release.get("generation_policy") != "current":
        raise ValueError("production release package identity is missing")
    release["generation"] = value["generation_id"]
    fd, temporary_name = tempfile.mkstemp(prefix=".kitpro-linux-release.", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(release, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
    return {"status": "passed", "generation": value["generation_id"], "package_count": 199}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    args = parser.parse_args()
    print(json.dumps(update(args.root), sort_keys=True))
