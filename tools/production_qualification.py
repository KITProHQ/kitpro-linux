#!/usr/bin/env python3
"""Build disposable production-trust test disks, without creating ISO media."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

from tools import kitpro_repo, kitpro_phase2, production_identity
from tools.install import INSTALLER_VERSION, engine, rootfs
from tools.install.model import parse_spec
from tools.install.receipt import build_receipt
from tools.production_repository import production_pacman_config

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def namespace_install_tools(work: Path) -> Path:
    """Reuse Arch's rootless mounts within the already established UID mapping."""
    destination = work / "namespace-tools"
    destination.mkdir(exist_ok=True)
    declaration = 'mount_unshare="$pid_unshare --mount --map-auto --map-root-user --setuid 0 --setgid 0"'
    for name in ("pacstrap", "arch-chroot"):
        original = Path("/usr/bin") / name
        text = original.read_text()
        if text.count(declaration) != 1 or text.count("unshare=0\n") != 1:
            raise ValueError("locked Arch install tool namespace contract changed")
        # Keep native unshare_setup (read-only sysfs bind and individual devices),
        # but reuse our subordinate UID mapping instead of requesting another.
        text = text.replace(declaration, 'mount_unshare="$pid_unshare --mount --setuid 0 --setgid 0"')
        text = text.replace("unshare=0\n", "unshare=1\n", 1)
        target = destination / name
        target.write_text(text)
        target.chmod(0o755)
    os.environ["PATH"] = str(destination) + ":" + os.environ["PATH"]
    return destination


def build(work: Path, generation_root: Path, public_package: Path, *, resume: bool = False) -> dict:
    mapping = [line.split() for line in Path("/proc/self/uid_map").read_text().splitlines()]
    if os.geteuid() != 0 or not any(row[0] == "0" and row[1] != "0" for row in mapping):
        raise ValueError("production qualification requires subordinate-UID namespace root, never host root")
    manifest = json.loads((generation_root / "manifest.json").read_text())
    if manifest["generation_id"] != "1.0-g0001" or manifest["qualification_state"] != "signed-awaiting-client-qualification":
        raise ValueError("baseline must be signed production g0001")
    work.mkdir(parents=True, exist_ok=resume)
    namespace_install_tools(work)
    root = work / "rootfs"
    root.mkdir(exist_ok=resume)
    key = work / "qualification_ed25519"
    if resume:
        password = (work / "guest-password").read_text()
        if not key.is_file() or (work / "baseline.raw").exists():
            raise ValueError("resume requires preserved guest key and no completed disk")
    else:
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kitpro-production-qualification", "-f", str(key)])
        # This password belongs only to the disposable guest, never the signer.
        password = uuid.uuid4().hex + "-Qualification"
        password_path = work / "guest-password"
        password_path.write_text(password)
        password_path.chmod(0o600)
        package_dir = work / "public-package"
        package_dir.mkdir()
        run(["bsdtar", "-xf", str(public_package), "-C", str(package_dir)])
        shutil.copytree(package_dir / "usr/share/pacman/keyrings", Path("/usr/share/pacman/keyrings"), dirs_exist_ok=True)
        gpgdir = root / "etc/pacman.d/gnupg"
        run(["pacman-key", "--gpgdir", str(gpgdir), "--init"])
        run(["pacman-key", "--gpgdir", str(gpgdir), "--populate", "archlinux", "kitpro-linux"])
        bootstrap = work / "bootstrap.conf"
        bootstrap.write_text(production_pacman_config().replace("[options]\n", f"[options]\nGPGDir = {gpgdir}\n"))
        explicit = [p["name"] for p in manifest["packages"] if p["explicit"]]
        run(["pacstrap", "-G", "-M", "-C", str(bootstrap), str(root), *explicit])
    # Confirm every installed package is from the exact signed current DB.
    production_identity.update(root)
    installed = kitpro_phase2.installed_packages(root)
    if installed != {p["name"]: p["version"] for p in manifest["packages"]}:
        raise ValueError("public bootstrap differs from g0001 manifest")
    for relative in ("efi/EFI/BOOT", "efi/EFI/systemd", "efi/loader/entries",
                     "etc/systemd/network", "etc/systemd/journald.conf.d", "var/log/journal"):
        (root / relative).mkdir(parents=True, exist_ok=True)
    kitpro_phase2.copy(ROOT / "config/rootfs/mkinitcpio.conf", root / "etc/mkinitcpio.conf")
    kitpro_phase2.copy(ROOT / "config/rootfs/10-persistent.conf", root / "etc/systemd/journald.conf.d/10-persistent.conf")
    efi = root / "usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    kitpro_phase2.copy(efi, root / "efi/EFI/BOOT/BOOTX64.EFI")
    kitpro_phase2.copy(efi, root / "efi/EFI/systemd/systemd-bootx64.efi")
    (root / "efi/loader/loader.conf").write_text("default kitpro-linux.conf\ntimeout 3\nconsole-mode keep\n")
    (root / "etc/machine-id").write_text("")
    spec = parse_spec({
        "version": 1, "release": {"name": "1.0", "generation": "1.0-g0001"},
        "system": {"hostname": "kitpro-production-qualification", "locale": "C.UTF-8", "timezone": "UTC"},
        "disk": {"device": str(work / "baseline.raw"), "target_type": "image", "layout": "standard", "filesystem": "ext4", "minimum_capacity_gib": 12},
        "network": {"mode": "dhcp"},
        "administrator": {"username": "kitpro-admin", "ssh_authorized_keys": [key.with_suffix(".pub").read_text().strip()]},
        "ssh": {"enabled": True}, "firewall": {"ssh": True}, "boot": {"mode": "uefi"},
    })
    plan = {"installer_version": INSTALLER_VERSION, "install_spec_sha256": spec.sha256(),
            "release": "1.0", "repository_generation": "1.0-g0001",
            "repository": {"package_count": 199, "generation_manifest_sha256": kitpro_repo.sha256_file(generation_root / "manifest.json")},
            "partition_table": {"esp": {"partition_uuid": str(uuid.uuid4())}, "root": {"partition_uuid": str(uuid.uuid4())}}}
    plan["plan_sha256"] = kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(plan))
    receipt = build_receipt(plan, kitpro_repo.utc_now(), {"kind": "production-repository-qualification", "source_git_commit": manifest["source"]["commit"]})
    rootfs.STATE_ROOT = work / "namespace-state"
    rootfs.configure_staging_rootfs(root, spec, plan, manifest["source"]["epoch"], receipt,
                                   "6.18.54-1", administrator_password=password)
    # Package cache contains public, signed bytes only. No build-worker trust is copied.
    if (root / "etc/pacman.conf").read_text() != production_pacman_config():
        raise ValueError("target repository configuration drift")
    definitions = engine.render_repart_definitions(work, plan)
    disk = work / "baseline.raw"
    with disk.open("xb") as stream:
        stream.truncate(16 * 1024**3)
    evidence = work / "disk-evidence"
    evidence.mkdir()
    # Already inside a subordinate-UID user/mount/PID namespace. Do not request
    # a second automatic UID mapping, or any host block device access.
    result = subprocess.run([
        "systemd-repart", "--dry-run=no", "--offline=yes", "--empty=force",
        f"--definitions={definitions}", f"--copy-source={root}", "--json=short", str(disk),
    ], env=engine._mtools_environment(), text=True, capture_output=True)
    (evidence / "systemd-repart.stdout").write_text(result.stdout)
    (evidence / "systemd-repart.stderr").write_text(result.stderr)
    result.check_returncode()
    if not isinstance(json.loads(result.stdout), list):
        raise ValueError("offline repart report must contain partition records")
    for acceleration in ("tcg", "kvm"):
        run(["cp", "--reflink=auto", "--sparse=always", str(disk), str(work / f"{acceleration}.raw")])
    return write_build_report(work, manifest)


def write_build_report(work: Path, manifest: dict) -> dict:
    root = work / "rootfs"
    for name in ("baseline.raw", "tcg.raw", "kvm.raw"):
        if (work / name).stat().st_size != 16 * 1024**3:
            raise ValueError("disposable raw disk size mismatch")
    report = {"status": "built-awaiting-boot", "generation": "1.0-g0001", "package_count": 199,
              "explicit_count": sum(p["explicit"] for p in manifest["packages"]), "kernel": "6.18.54-1",
              "manifest_sha256": kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(manifest)),
              "runtime_sha256": {p.relative_to(root).as_posix(): kitpro_repo.sha256_file(p) for p in
                                  (root / "usr/lib/kitpro-linux/repository-identity", root / "usr/lib/kitpro-linux/kernel-boot-validate", root / "usr/lib/kitpro-linux/kernel-lifecycle",
                                   root / "usr/lib/kitpro-linux/system-health", root / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py")}}
    kitpro_repo.atomic_write_json(work / "baseline-build.json", report)
    return report



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--generation", type=Path, required=True)
    parser.add_argument("--keyring-package", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.work, args.generation, args.keyring_package, resume=args.resume), indent=2))
