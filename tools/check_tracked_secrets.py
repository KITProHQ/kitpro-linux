#!/usr/bin/env python3
"""Reject private signing material and generated state tracked by Git."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PATH_PARTS = {
    ".state",
    "private-keys-v1.d",
    "openpgp-revocs.d",
    "gnupg-private",
    "signing-home",
}
FORBIDDEN_SUFFIXES = {".key", ".sec"}
FORBIDDEN_FILENAMES = {
    "secring.gpg",
    "private-keys-v1.d",
    "trustdb.gpg",
}
FORBIDDEN_BACKUP_SUFFIXES = {
    ".backup.gpg",
    ".private.gpg",
    ".secret.gpg",
}


def tracked_paths(root: Path = PROJECT_ROOT) -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [root / value.decode() for value in result.stdout.split(b"\0") if value]


def violations(paths: list[Path], root: Path = PROJECT_ROOT) -> list[str]:
    private_markers = (
        b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----",
        b"-----BEGIN PGP " + b"SECRET KEY BLOCK-----",
    )
    problems: list[str] = []
    for path in paths:
        relative = path.relative_to(root)
        if FORBIDDEN_PATH_PARTS.intersection(relative.parts):
            problems.append(f"generated or private state is tracked: {relative}")
        if path.name in FORBIDDEN_FILENAMES:
            problems.append(f"GnuPG private state filename is tracked: {relative}")
        if path.suffix in FORBIDDEN_SUFFIXES:
            problems.append(f"private-key filename is tracked: {relative}")
        if any(path.name.endswith(suffix) for suffix in FORBIDDEN_BACKUP_SUFFIXES):
            problems.append(f"encrypted private-key backup is tracked: {relative}")
        if path.is_symlink():
            continue
        try:
            content = path.read_bytes()
        except OSError as error:
            problems.append(f"cannot inspect tracked file {relative}: {error}")
            continue
        if any(marker in content for marker in private_markers):
            problems.append(f"private OpenPGP material is tracked: {relative}")
    return problems


def main() -> int:
    problems = violations(tracked_paths())
    if problems:
        print("tracked-secret check failed:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    print("tracked-secret check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
