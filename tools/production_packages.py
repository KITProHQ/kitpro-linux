#!/usr/bin/env python3
"""Prepare production package sources from the pinned public ceremony export.

This module never signs, publishes, generates keys, or connects to the signer.
GnuPG is used only in a disposable public-key verification home.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from tools.production_repository import production_pacman_config

ROOT = Path(__file__).resolve().parents[1]
EXPORT_SHA256 = "ed1a73a0d4cb2cceb5f98f8bb80d6fa4c566db80d7a04bd18381e7d972c0a495"
FINGERPRINTS = {
    "root": "913BDB5D1E06A5B57F46F5B674DAF522F825A435",
    "recovery": "A785847E90D66198B26E9F4588F26422E49B3FFA",
    "package": "4742B8D5550858F1723C8E0DB0DCE551DDD9F456",
    "repository": "52BADA3613798054B7E35840DC088D21DA29F538",
    "iso": "607D71E399E645164471C8EBA998AA6B6095B621",
}
PACMAN_ROLES = ("root", "package", "repository")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_packets(armor: bytes) -> bytes:
    """Reject secret packets before any key material reaches GnuPG."""
    text = armor.decode("ascii")
    match = re.fullmatch(
        r"-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n(?:[^\n]+\r?\n)*?\r?\n"
        r"([A-Za-z0-9+/=\r\n]+)-----END PGP PUBLIC KEY BLOCK-----\s*", text
    )
    if not match:
        raise ValueError("expected exactly one public-key armor block")
    lines = [line for line in match[1].splitlines() if not line.startswith("=")]
    data = base64.b64decode("".join(lines), validate=True)
    offset = 0
    tags = []
    while offset < len(data):
        header = data[offset]
        offset += 1
        if not header & 0x80:
            raise ValueError("invalid OpenPGP packet header")
        if header & 0x40:
            tag = header & 0x3f
            if offset >= len(data):
                raise ValueError("truncated packet length")
            first = data[offset]
            offset += 1
            if first < 192:
                size = first
            elif first < 224:
                if offset >= len(data):
                    raise ValueError("truncated packet length")
                size = (first - 192) * 256 + data[offset] + 192
                offset += 1
            elif first == 255:
                if offset + 4 > len(data):
                    raise ValueError("truncated packet length")
                size = int.from_bytes(data[offset:offset + 4], "big")
                offset += 4
            else:
                raise ValueError("partial packet length is not accepted")
        else:
            tag = (header >> 2) & 15
            length_type = header & 3
            if length_type == 3:
                raise ValueError("indeterminate packet length is not accepted")
            count = 1 << length_type
            if offset + count > len(data):
                raise ValueError("truncated packet length")
            size = int.from_bytes(data[offset:offset + count], "big")
            offset += count
        if tag in (5, 7):
            raise ValueError("secret OpenPGP packet rejected")
        if tag not in (2, 6, 13, 14, 17) or offset + size > len(data):
            raise ValueError("unexpected or truncated public key packet")
        tags.append(tag)
        offset += size
    if tags.count(6) != 1:
        raise ValueError("expected one primary public key")
    return data


def read_public_export(archive: Path) -> tuple[dict[str, bytes], dict]:
    if sha256(archive.read_bytes()) != EXPORT_SHA256:
        raise ValueError("production trust export hash mismatch")
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)):
            raise ValueError("duplicate export member")
        keys = {}
        for role in FINGERPRINTS:
            member = bundle.getmember(f"public-export/keys/{role}.asc")
            if not member.isfile() or member.size > 100_000:
                raise ValueError("invalid public key export member")
            armor = bundle.extractfile(member).read()
            public_packets(armor)
            keys[role] = armor
        manifest_member = bundle.getmember("public-export/production-trust-manifest.json")
        if not manifest_member.isfile() or manifest_member.size > 100_000:
            raise ValueError("invalid trust manifest member")
        manifest = json.load(bundle.extractfile(manifest_member))
    if {key["role"]: key["fingerprint"] for key in manifest["keys"]} != FINGERPRINTS:
        raise ValueError("ceremony manifest fingerprint mismatch")
    return keys, manifest


def verify_public_keys(keys: dict[str, bytes]) -> dict:
    with tempfile.TemporaryDirectory(prefix="kitpro-public-verify-") as temporary:
        home = Path(temporary)

        def gpg(*args: str, data: bytes | None = None) -> bytes:
            return subprocess.run(
                ["gpg", "--no-options", "--homedir", str(home), "--batch",
                 "--no-auto-key-retrieve", "--no-autostart", *args], input=data, check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout

        for role, armor in keys.items():
            public_packets(armor)
            listing = gpg("--with-colons", "--show-keys", data=armor).decode()
            fingerprints = [line.split(":")[9] for line in listing.splitlines()
                            if line.startswith("fpr:")]
            if fingerprints != [FINGERPRINTS[role]]:
                raise ValueError(f"unexpected primary/subkey fingerprint for {role}")
            if "TEST" in listing or "DEVELOPMENT" in listing:
                raise ValueError("test/development public key rejected")
            gpg("--import", data=armor)
        for role in ("package", "repository", "iso"):
            listing = gpg("--with-colons", "--check-sigs", FINGERPRINTS[role]).decode()
            signatures = [line.split(":") for line in listing.splitlines()
                          if line.startswith("sig:!")]
            if not any(row[4] == FINGERPRINTS["root"][-16:] for row in signatures):
                raise ValueError(f"valid Root certification missing for {role}")
        if gpg("--with-colons", "--list-secret-keys").strip():
            raise ValueError("public verification home contains a secret key")
    return {"fingerprints": FINGERPRINTS, "root_certifications": "verified",
            "secret_packets": False, "test_or_development_keys": False}


def write_package(directory: Path, name: str, description: str,
                  files: dict[str, tuple[bytes, str]], *, depends: str = "",
                  install_script: str | None = None) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    for filename, (data, _) in files.items():
        (directory / filename).write_bytes(data)
    sources = " ".join(repr(name) for name in files)
    sums = " ".join(repr(sha256(data)) for data, _ in files.values())
    installs = "\n".join(
        f'    install -Dm644 "$srcdir/{filename}" "$pkgdir/{target}"'
        for filename, (_, target) in files.items()
    )
    text = (f"pkgname={name}\npkgver=1.0\npkgrel=1\npkgdesc='{description}'\n"
            "arch=('any')\nlicense=('Apache-2.0')\noptions=('!debug')\n"
            f"depends=({depends})\nsource=({sources})\nsha256sums=({sums})\n")
    if install_script is not None:
        text += f"install={name}.install\n"
        (directory / f"{name}.install").write_text(install_script)
    text += f"\npackage() {{\n{installs or '    :'}\n}}\n"
    (directory / "PKGBUILD").write_text(text)


def prepare(archive: Path, output: Path) -> dict:
    if output.exists():
        raise ValueError("package source destination already exists")
    keys, ceremony = read_public_export(archive)
    verification = verify_public_keys(keys)
    # ISO and Recovery remain metadata only. Pacman's keyring cannot trust them.
    keyring = b"".join(public_packets(keys[role]) for role in PACMAN_ROLES)
    # One certified production Root is the trust anchor. Ownertrust 4 would
    # require three independent marginal introducers and leave delegates marginal.
    trust = (FINGERPRINTS["root"] + ":5:\n").encode()
    manifest = {"schema_version": 1, "release": "1.0", "keys": ceremony["keys"],
                "pacman_key_roles": list(PACMAN_ROLES),
                "package_authorities": [FINGERPRINTS["package"]],
                "repository_authorities": [FINGERPRINTS["repository"]]}
    output.mkdir(parents=True)
    write_package(output / "kitpro-linux-keyring", "kitpro-linux-keyring",
                  "KITPro Linux Server production public trust", {
        "kitpro-linux.gpg": (keyring, "usr/share/pacman/keyrings/kitpro-linux.gpg"),
        "kitpro-linux-trusted": (trust, "usr/share/pacman/keyrings/kitpro-linux-trusted"),
        "kitpro-linux-revoked": (b"", "usr/share/pacman/keyrings/kitpro-linux-revoked"),
        "production-trust.json": ((json.dumps(manifest, indent=2) + "\n").encode(),
                                  "usr/share/kitpro-linux/production-trust.json"),
    }, depends="'pacman' 'gnupg'", install_script=(
        "post_install() {\n    pacman-key --populate kitpro-linux\n}\n"
        "post_upgrade() {\n    post_install\n}\n"))
    release = {"schema_version": 1, "id": "kitpro-linux", "name": "KITPro Linux Server",
               "release": "1.0", "channel": "stable", "generation_policy": "current",
               "support_status": "release-candidate-preparation", "production_ready": False}
    os_release = ('NAME="KITPro Linux Server"\nPRETTY_NAME="KITPro Linux Server 1.0"\n'
                  'ID=kitpro-linux\nID_LIKE=arch\nVERSION_ID="1.0"\n'
                  'HOME_URL="https://kitpro.us/"\n')
    write_package(output / "kitpro-linux-release", "kitpro-linux-release",
                  "KITPro Linux Server 1.0 release identity", {
        "release.json": ((json.dumps(release, indent=2) + "\n").encode(),
                         "usr/lib/kitpro-linux/release.json"),
        "pacman.conf": (production_pacman_config().encode(), "usr/share/kitpro-linux/pacman.conf"),
        "os-release": (os_release.encode(), "usr/share/kitpro-linux/os-release"),
    }, depends="'kitpro-linux-keyring'", install_script=(
        "post_install() {\n"
        "    install -Dm644 /usr/lib/kitpro-linux/release.json /etc/kitpro-linux-release.json\n"
        "    install -Dm644 /usr/share/kitpro-linux/pacman.conf /etc/pacman.conf\n"
        "    install -Dm644 /usr/share/kitpro-linux/os-release /usr/lib/os-release\n"
        "    ln -sfn ../usr/lib/os-release /etc/os-release\n}\n"
        "post_upgrade() {\n    post_install\n}\n"))
    # Preserve the frozen dependency contract and explicit package count.
    base = (ROOT / "packages/kitpro-linux-base/PKGBUILD").read_text()
    base = base.replace("pkgver=0.1.0", "pkgver=1.0").replace("pkgrel=6", "pkgrel=1")
    (output / "kitpro-linux-base").mkdir()
    (output / "kitpro-linux-base/PKGBUILD").write_text(base)
    write_package(output / "kitpro-linux-repository-trust", "kitpro-linux-repository-trust",
                  "KITPro Linux Server public WebPKI repository trust", {},
                  depends="'ca-certificates' 'kitpro-linux-keyring'")
    return {"status": "prepared-unsigned", "export_sha256": EXPORT_SHA256,
            "verification": verification, "version": "1.0-1",
            "packages": sorted(path.name for path in output.iterdir())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_export", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.public_export, args.output), indent=2))


if __name__ == "__main__":
    main()
