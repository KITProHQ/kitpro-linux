"""Transient local-console password handling for installation."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from tools import kitpro_repo
from tools.install.model import validate_password_hash


def validate_plaintext_password(value: str) -> str:
    """Validate an in-memory password without logging or persisting it."""
    if value == "":
        raise kitpro_repo.PipelineError(
            "local-console password must not be empty"
        )
    if any(character in value for character in ("\0", "\n", "\r", ":")):
        raise kitpro_repo.PipelineError(
            "local-console password contains an unsupported character"
        )
    if len(value) > 128:
        raise kitpro_repo.PipelineError(
            "local-console password must contain no more than 128 characters"
        )
    return value


def configure_account_password(
    root: Path,
    username: str,
    *,
    plaintext: str | None = None,
    password_hash: str | None = None,
) -> None:
    """Set one target password through stdin, never argv or an intermediate file."""
    if plaintext is not None and password_hash is not None:
        raise kitpro_repo.PipelineError(
            "local-console password and precomputed hash are mutually exclusive"
        )
    if plaintext is None and password_hash is None:
        return
    if plaintext is not None:
        credential = validate_plaintext_password(plaintext)
        command = [
            "chpasswd",
            "--prefix",
            str(root),
            "--crypt-method",
            "YESCRYPT",
        ]
    else:
        credential = validate_password_hash(password_hash or "")
        command = ["chpasswd", "--prefix", str(root), "--encrypted"]
    completed = subprocess.run(
        command,
        input=f"{username}:{credential}\n",
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            "failed to enroll the local-console administrator password"
        )
    shadow = root / "etc/shadow"
    entry = next(
        (line.split(":", 2)[1] for line in shadow.read_text().splitlines() if line.startswith(f"{username}:")),
        None,
    )
    if entry is None:
        raise kitpro_repo.PipelineError(
            "local-console administrator shadow entry is missing"
        )
    if plaintext is not None and not entry.startswith("$y$"):
        raise kitpro_repo.PipelineError(
            "local-console administrator password was not hashed with yescrypt"
        )
    if password_hash is not None and entry != password_hash:
        raise kitpro_repo.PipelineError(
            "precomputed local-console password hash was not installed exactly"
        )


def hash_password(password: str, username: str = "kitpro-password-fixture") -> str:
    """Generate a transient yescrypt hash without placing plaintext in argv or a file."""
    validate_plaintext_password(password)
    with tempfile.TemporaryDirectory(prefix="kitpro-password-") as name:
        root = Path(name)
        etc = root / "etc"
        etc.mkdir(mode=0o700)
        (etc / "passwd").write_text(
            f"{username}:x:1000:1000:KITPro password fixture:/nonexistent:/usr/bin/nologin\n"
        )
        shadow = etc / "shadow"
        shadow.write_text(f"{username}:!:1:0:99999:7:::\n")
        shadow.chmod(0o600)
        configure_account_password(root, username, plaintext=password)
        value = next(
            line.split(":", 2)[1]
            for line in shadow.read_text().splitlines()
            if line.startswith(f"{username}:")
        )
    return validate_password_hash(value)
