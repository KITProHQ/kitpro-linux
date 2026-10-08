#!/usr/bin/env python3
"""Build and validate the KITPro Linux Phase 2 root filesystem and disk image."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any, Sequence

from tools import kitpro_repo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = PROJECT_ROOT / "config/rootfs-profile.json"
DEFAULT_REPO_ROOT = PROJECT_ROOT / "repo"
DEFAULT_STATE_ROOT = PROJECT_ROOT / ".state/phase2"
DEFAULT_ARTIFACT_ROOT = PROJECT_ROOT / ".state/phase2/artifacts"
REPOSITORY_POLICY = PROJECT_ROOT / "runtime/repository-policy.conf"


def load_repository_policy(path: Path = REPOSITORY_POLICY) -> dict[str, str]:
    """Parse the fixed shell-compatible policy as data without executing it."""
    result: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z_]+", key):
            raise kitpro_repo.PipelineError("repository policy contains an invalid assignment")
        values = shlex.split(raw_value)
        if len(values) != 1:
            raise kitpro_repo.PipelineError(f"repository policy value is invalid: {key}")
        result[key] = values[0]
    required = {
        "KITPRO_REPOSITORY_PREFIX", "ARCH_REPOSITORIES", "REQUIRED_SIGLEVEL",
        "REQUIRED_LOCAL_FILE_SIGLEVEL", "FORBIDDEN_REPOSITORY_TERMS",
    }
    if set(result) != required:
        raise kitpro_repo.PipelineError("repository policy fields are incomplete")
    return result


_REPOSITORY_POLICY = load_repository_policy()
ARCH_REPOSITORIES = set(_REPOSITORY_POLICY["ARCH_REPOSITORIES"].split())


def command_version(command: Sequence[str]) -> str:
    completed = subprocess.run(
        list(command), text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    return lines[0] if lines else "unavailable"


def pacstrap_version(state_root: Path) -> str:
    packages = sorted((state_root / "host-packages").glob("arch-install-scripts-*.pkg.tar.*"))
    packages = [path for path in packages if not path.name.endswith(".sig")]
    if packages:
        metadata, _ = kitpro_repo.package_metadata(packages[-1])
        return f"arch-install-scripts {kitpro_repo.first(metadata, 'pkgver')}"
    return "arch-install-scripts version unavailable"


def run(command: Sequence[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return kitpro_repo.run(command, cwd=cwd)


def run_in_root_namespace(
    root: Path, command: Sequence[str], state_root: Path
) -> subprocess.CompletedProcess[str]:
    installed = shutil.which("arch-chroot")
    chroot_tool = Path(installed) if installed else state_root / "host-tools/usr/bin/arch-chroot"
    if not chroot_tool.is_file():
        raise kitpro_repo.PipelineError("arch-chroot is unavailable from arch-install-scripts")
    namespace_option = [] if os.geteuid() == 0 else ["-N"]
    return run([str(chroot_tool), *namespace_option, str(root), *command])


def write(path: Path, value: str, mode: int = 0o644) -> None:
    kitpro_repo.atomic_write(path, value.encode(), mode)


def copy(source: Path, destination: Path, mode: int | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if mode is not None:
        destination.chmod(mode)


def directory_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def parse_enabled_repositories(config: Path) -> list[str]:
    repositories: list[str] = []
    for raw_line in config.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith("["):
            continue
        section = line.removeprefix("[").removesuffix("]")
        if section.lower() != "options":
            repositories.append(section)
    return repositories


def validate_repository_isolation(config: Path) -> list[str]:
    text = config.read_text()
    repositories = parse_enabled_repositories(config)
    forbidden = sorted(set(repositories) & ARCH_REPOSITORIES)
    if forbidden:
        raise kitpro_repo.PipelineError(f"Arch repositories are enabled: {', '.join(forbidden)}")
    prefix = _REPOSITORY_POLICY["KITPRO_REPOSITORY_PREFIX"]
    if not repositories or any(not repository.startswith(prefix) for repository in repositories):
        raise kitpro_repo.PipelineError(f"non-KITPro repository is enabled: {repositories}")
    required = (
        _REPOSITORY_POLICY["REQUIRED_SIGLEVEL"],
        _REPOSITORY_POLICY["REQUIRED_LOCAL_FILE_SIGLEVEL"],
    )
    if any(line not in text for line in required):
        raise kitpro_repo.PipelineError("pacman signature enforcement is incomplete")
    lowered = text.lower()
    if any(
        term.lower() in lowered
        for term in _REPOSITORY_POLICY["FORBIDDEN_REPOSITORY_TERMS"].split()
    ):
        raise kitpro_repo.PipelineError("pacman configuration contains a fallback repository")
    return repositories


def validate_rootfs_preflight(root: Path) -> None:
    required = {
        "kernel": root / "boot/vmlinuz-linux-lts",
        "initramfs": root / "boot/initramfs-linux-lts.img",
        "UEFI bootloader": root / "efi/EFI/BOOT/BOOTX64.EFI",
        "boot entry": root / "efi/loader/entries/kitpro-linux.conf",
        "DHCP network configuration": root / "etc/systemd/network/20-wired-dhcp.network",
        "static network configuration": root / "etc/systemd/network/20-wired-static.network.disabled",
        "nftables configuration": root / "etc/nftables.conf",
        "sshd configuration": root / "etc/ssh/sshd_config.d/10-kitpro-server.conf",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    if missing:
        raise kitpro_repo.PipelineError(f"rootfs preflight misses: {', '.join(missing)}")
    boot = required["boot entry"].read_text()
    if "linux /vmlinuz-linux-lts" not in boot or "root=PARTUUID=" not in boot:
        raise kitpro_repo.PipelineError("boot entry does not identify the kernel and root partition")
    dhcp = required["DHCP network configuration"].read_text()
    static = required["static network configuration"].read_text()
    if "[Match]" not in dhcp or "DHCP=yes" not in dhcp:
        raise kitpro_repo.PipelineError("DHCP network configuration is invalid")
    if not all(value in static for value in ("Address=", "Gateway=", "DNS=")):
        raise kitpro_repo.PipelineError("static network configuration is invalid")
    nftables = required["nftables configuration"].read_text()
    if not all(value in nftables for value in ("policy drop", 'iifname "lo" accept', "established,related", "tcp dport 22")):
        raise kitpro_repo.PipelineError("nftables baseline is invalid")
    sshd = required["sshd configuration"].read_text()
    if not all(
        value in sshd
        for value in ("PermitRootLogin no", "PasswordAuthentication no", "PubkeyAuthentication yes")
    ):
        raise kitpro_repo.PipelineError("sshd baseline is invalid")
    resolv = root / "etc/resolv.conf"
    if not resolv.is_symlink() or os.readlink(resolv) != "../run/systemd/resolve/stub-resolv.conf":
        raise kitpro_repo.PipelineError("systemd-resolved resolv.conf link is invalid")
    validate_repository_isolation(root / "etc/pacman.conf")


def validate_rootfs_manifest(document: dict[str, Any]) -> None:
    required = {
        "schema_version", "kitpro_release", "stable_generation", "architecture",
        "explicit_packages", "resolved_package_count", "packages", "kernel",
        "initramfs", "bootloader", "filesystem", "root_filesystem_uuid",
        "network", "ssh", "nftables", "enabled_systemd_units", "build_timestamp",
        "build_tools", "rootfs_size_bytes", "disk_image", "test_results",
    }
    missing = sorted(required - document.keys())
    if missing:
        raise kitpro_repo.PipelineError(f"rootfs manifest misses fields: {missing}")
    if document["schema_version"] != 1 or document["architecture"] != "x86_64":
        raise kitpro_repo.PipelineError("unsupported rootfs manifest architecture or schema")
    if document["resolved_package_count"] != len(document["packages"]):
        raise kitpro_repo.PipelineError("rootfs manifest package count is inconsistent")
    for package in document["packages"]:
        if not re.fullmatch(r"[0-9a-f]{64}", package.get("sha256", "")):
            raise kitpro_repo.PipelineError(f"invalid package hash: {package.get('name')}")
    for field in ("image_sha256",):
        if not re.fullmatch(r"[0-9a-f]{64}", document["kernel"].get(field, "")):
            raise kitpro_repo.PipelineError(f"invalid kernel {field}")
    if not re.fullmatch(r"[0-9a-f]{64}", document["initramfs"].get("sha256", "")):
        raise kitpro_repo.PipelineError("invalid initramfs hash")


def generation(profile: dict[str, Any], repo_root: Path) -> tuple[Path, dict[str, Any]]:
    root = repo_root / "stable" / profile["release"] / profile["generation"]
    manifest = kitpro_repo.load_json(root / "manifest.json")
    kitpro_repo.validate_manifest(manifest)
    if manifest["generation_id"] != profile["generation"]:
        raise kitpro_repo.PipelineError("profile and Stable generation do not match")
    return root, manifest


def pacstrap_path(state_root: Path) -> Path:
    installed = shutil.which("pacstrap")
    if installed:
        return Path(installed)
    local = state_root / "host-tools/usr/bin/pacstrap"
    if local.is_file():
        return local
    raise kitpro_repo.PipelineError(
        "pacstrap is unavailable; install arch-install-scripts in the disposable Phase 2 host-tools root"
    )


def bootstrap_pacstrap(state_root: Path, artifact_root: Path) -> dict[str, Any]:
    filename = "arch-install-scripts-31-2-any.pkg.tar.zst"
    expected = {
        filename: "21844567f7811bb957cb57982c697ff6a466a13ea3c8ad2cd159a7603c83608e",
        filename + ".sig": "1ea8adf9657c03ffa11af114babce8dee8269abb166a19ed8aa43b0892fbb00f",
    }
    package_root = state_root / "host-packages"
    tool_root = state_root / "host-tools"
    package = package_root / filename
    signature = package_root / (filename + ".sig")
    base_url = "https://archive.archlinux.org/packages/a/arch-install-scripts"
    for path in (package, signature):
        kitpro_repo.download(f"{base_url}/{path.name}", path)
        if kitpro_repo.sha256_file(path) != expected[path.name]:
            raise kitpro_repo.PipelineError(f"pinned host-tool hash changed: {path.name}")
    signer = kitpro_repo.verify_signature(
        PROJECT_ROOT / ".state/ingest/2026-09-24/arch-gnupg", signature, package
    )
    pacstrap = tool_root / "usr/bin/pacstrap"
    if not pacstrap.is_file():
        tool_root.mkdir(parents=True, exist_ok=True)
        run(["bsdtar", "-xf", str(package), "-C", str(tool_root)])
    report = {
        "schema_version": 1,
        "package": filename,
        "package_sha256": expected[filename],
        "signature_sha256": expected[filename + ".sig"],
        "signer_fingerprint": signer,
        "source": f"{base_url}/{filename}",
        "development_host_only": True,
    }
    artifact_root.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(artifact_root / "pacstrap-bootstrap.json", report)
    return report


def bootstrap_vm_tools(state_root: Path, artifact_root: Path) -> dict[str, Any]:
    """Install QEMU/OVMF/mtools in an ignored, signature-verified Arch tool root."""
    snapshot_date = "2026/09/24"
    output = state_root / "vm-tools"
    marker = output / "usr/bin/qemu-system-x86_64"
    manifest_path = artifact_root / "vm-tools-manifest.json"
    if marker.is_file() and (output / "usr/bin/mcopy").is_file() and manifest_path.is_file():
        return kitpro_repo.load_json(manifest_path)
    if output.exists():
        raise kitpro_repo.PipelineError(f"refusing to replace incomplete VM tool root: {output}")
    output.mkdir(parents=True)
    cache = state_root / "vm-tools-cache"
    cache.mkdir(parents=True, exist_ok=True)
    (state_root / "log").mkdir(parents=True, exist_ok=True)
    config = state_root / "vm-tools-pacman.conf"
    arch_gpg = PROJECT_ROOT / ".state/ingest/2026-09-24/arch-gnupg"
    kitpro_repo.render_template(
        PROJECT_ROOT / "config/host-tools-pacman.conf.in",
        config,
        {
            "CACHE_PATH": str(cache.resolve()),
            "ARCH_GPG_PATH": str(arch_gpg.resolve()),
            "LOG_PATH": str((state_root / "log/vm-tools-pacman.log").resolve()),
            "SNAPSHOT_DATE": snapshot_date,
        },
    )
    run(
        [
            str(pacstrap_path(state_root)), "-N", "-G", "-M", "-C", str(config), str(output),
            "mtools", "qemu-system-x86", "qemu-img", "edk2-ovmf",
        ]
    )
    packages = installed_packages(output)
    package_files = sorted(cache.glob("*.pkg.tar.*"))
    package_files = [path for path in package_files if not path.name.endswith(".sig")]
    report = {
        "schema_version": 1,
        "purpose": "Phase 2 host-only QEMU, OVMF, and image construction tools",
        "source": f"Arch Linux Archive {snapshot_date}",
        "guest_package_source": False,
        "signature_policy": "packages required and trusted; Archive database signatures unavailable",
        "packages": [{"name": name, "version": version} for name, version in sorted(packages.items())],
        "cached_artifacts": [
            {"filename": path.name, "sha256": kitpro_repo.sha256_file(path)} for path in package_files
        ],
    }
    artifact_root.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(manifest_path, report)
    return report


def configure_rootfs(
    root: Path,
    profile: dict[str, Any],
    source_epoch: int,
    state_root: Path,
) -> tuple[Path | None, list[str]]:
    source = PROJECT_ROOT / "config/rootfs"
    for path in (
        root / "etc/systemd/network",
        root / "etc/systemd/resolved.conf.d",
        root / "etc/systemd/journald.conf.d",
        root / "etc/ssh/sshd_config.d",
        root / "etc/sudoers.d",
        root / "etc/pacman.d/gnupg",
        root / "var/log/journal",
        root / "efi/EFI/systemd",
        root / "efi/EFI/BOOT",
        root / "efi/loader/entries",
    ):
        path.mkdir(parents=True, exist_ok=True)

    write(root / "etc/hostname", profile["hostname"] + "\n")
    write(
        root / "etc/hosts",
        "127.0.0.1 localhost\n::1 localhost\n127.0.1.1 " + profile["hostname"] + "\n",
    )
    write(root / "etc/locale.conf", "LANG=C.UTF-8\n")
    localtime = root / "etc/localtime"
    localtime.unlink(missing_ok=True)
    os.symlink("../usr/share/zoneinfo/UTC", localtime)

    os_release = (
        'NAME="KITPro Linux Server"\n'
        'PRETTY_NAME="KITPro Linux Server 0.1 development prototype"\n'
        'ID=kitpro-linux\n'
        'ID_LIKE=arch\n'
        'VERSION_ID="0.1-dev"\n'
        f'BUILD_ID="{profile["generation"]}"\n'
        'ANSI_COLOR="38;2;52;120;246"\n'
        'HOME_URL="https://kitpro.us/"\n'
        'DOCUMENTATION_URL="https://github.com/KITProHQ/kitpro-linux"\n'
    )
    write(root / "usr/lib/os-release", os_release)
    etc_os_release = root / "etc/os-release"
    etc_os_release.unlink(missing_ok=True)
    os.symlink("../usr/lib/os-release", etc_os_release)
    release_metadata = {
        "schema_version": 1,
        "release": profile["release"],
        "generation": profile["generation"],
        "channel": "stable",
        "production_ready": False,
    }
    kitpro_repo.atomic_write_json(root / "etc/kitpro-linux-release.json", release_metadata)

    pacman_text = (source / "pacman.conf.in").read_text()
    pacman_text = pacman_text.replace("@RELEASE@", profile["release"])
    pacman_text = pacman_text.replace("@REPOSITORY_URL@", profile["repository_url"])
    write(root / "etc/pacman.conf", pacman_text)
    repositories = validate_repository_isolation(root / "etc/pacman.conf")
    kitpro_repo.initialize_public_keyring(
        root / "etc/pacman.d/gnupg",
        root / "usr/share/pacman/keyrings/kitpro-linux.gpg",
        root / "usr/share/pacman/keyrings/kitpro-linux-trusted",
        root / "usr/share/pacman/keyrings/kitpro-linux-revoked",
    )

    copy(source / "20-wired-dhcp.network", root / "etc/systemd/network/20-wired-dhcp.network")
    copy(
        source / "20-wired-static.network.disabled",
        root / "etc/systemd/network/20-wired-static.network.disabled",
    )
    resolv_conf = root / "etc/resolv.conf"
    resolv_conf.unlink(missing_ok=True)
    os.symlink("../run/systemd/resolve/stub-resolv.conf", resolv_conf)
    copy(source / "nftables.conf", root / "etc/nftables.conf", 0o755)
    copy(source / "10-kitpro-server.conf", root / "etc/ssh/sshd_config.d/10-kitpro-server.conf")
    copy(source / "10-persistent.conf", root / "etc/systemd/journald.conf.d/10-persistent.conf")
    copy(source / "mkinitcpio.conf", root / "etc/mkinitcpio.conf")

    private_key: Path | None = None
    if profile.get("create_administrator_fixture", True):
        sysusers = root / "usr/lib/sysusers.d/kitpro-phase2-admin.conf"
        write(
            sysusers,
            f"g {profile['administrator']} 1000\n"
            f"u {profile['administrator']} 1000:1000 'KITPro test administrator' /home/{profile['administrator']} /bin/bash\n"
            f"m {profile['administrator']} wheel\n",
        )
        run(["systemd-sysusers", f"--root={root}"])
        if not any(
            line.startswith(f"{profile['administrator']}:")
            for line in (root / "etc/passwd").read_text().splitlines()
        ):
            raise kitpro_repo.PipelineError("systemd-sysusers did not create the test administrator")
        administrator_home = root / "home" / profile["administrator"]
        administrator_home.mkdir(parents=True, exist_ok=True)
        ssh_dir = administrator_home / ".ssh"
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        key_root = state_root / "keys"
        key_root.mkdir(parents=True, exist_ok=True)
        private_key = key_root / "phase2_admin_ed25519"
        if not private_key.exists():
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "kitpro-phase2-disposable", "-f", str(private_key)])
        public_key = private_key.with_suffix(".pub").read_text().strip() + "\n"
        write(ssh_dir / "authorized_keys", public_key, 0o600)
        write(
            root / "etc/sudoers.d/10-kitpro-phase2-admin",
            f"{profile['administrator']} ALL=(ALL:ALL) NOPASSWD: ALL\n",
            0o440,
        )
        run(
            [
                "unshare", "--fork", "--pid", "--mount", "--map-auto", "--map-root-user",
                "chown", "-R", "1000:1000", str(administrator_home),
            ]
        )

    enabled = [
        "systemd-networkd.service",
        "systemd-resolved.service",
        "systemd-timesyncd.service",
        "nftables.service",
        "getty@tty1.service",
        "serial-getty@ttyS0.service",
    ]
    if profile.get("enable_sshd", True):
        enabled.append("sshd.service")
    run(["systemctl", f"--root={root}", "enable", *enabled])
    run(["systemctl", f"--root={root}", "set-default", "multi-user.target"])
    write(root / "etc/machine-id", "")
    write(root / "var/lib/systemd/random-seed", "", 0o600)

    run_in_root_namespace(
        root,
        ["/usr/bin/env", f"SOURCE_DATE_EPOCH={source_epoch}", "mkinitcpio", "-P"],
        state_root,
    )

    efi_binary = root / "usr/lib/systemd/boot/efi/systemd-bootx64.efi"
    copy(efi_binary, root / "efi/EFI/systemd/systemd-bootx64.efi")
    copy(efi_binary, root / "efi/EFI/BOOT/BOOTX64.EFI")
    copy(root / "boot/vmlinuz-linux-lts", root / "efi/vmlinuz-linux-lts")
    copy(root / "boot/initramfs-linux-lts.img", root / "efi/initramfs-linux-lts.img")
    write(root / "efi/loader/loader.conf", "default kitpro-linux.conf\ntimeout 1\nconsole-mode keep\n")
    write(
        root / "efi/loader/entries/kitpro-linux.conf",
        "title KITPro Linux Server 0.1 development\n"
        "linux /vmlinuz-linux-lts\n"
        "initrd /initramfs-linux-lts.img\n"
        f"options root=PARTUUID={profile['root_partition_uuid']} rw "
        "console=ttyS0,115200n8 console=tty0\n",
    )
    return private_key, repositories


def installed_packages(root: Path) -> dict[str, str]:
    result = run(["pacman", "--root", str(root), "--dbpath", str(root / "var/lib/pacman"), "-Q"])
    packages: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, version = line.split(" ", 1)
        packages[name] = version
    return packages


def build_rootfs(
    profile_path: Path,
    repo_root: Path,
    state_root: Path,
    output: Path,
    artifact_root: Path,
    *,
    mounted_target: bool = False,
) -> dict[str, Any]:
    profile = kitpro_repo.load_json(profile_path)
    generation_root, generation_manifest = generation(profile, repo_root)
    kitpro_repo.verify_manifest_artifacts(
        generation_manifest, repo_root, generation_root, PROJECT_ROOT / ".state/dev-keys"
    )
    marker = output / ".kitpro-phase2-build-root"
    if mounted_target:
        if not output.is_mount() or any(
            path.name not in {"lost+found", "efi", ".kitpro-install-work"}
            or path.is_symlink() or not path.is_dir()
            for path in output.iterdir()
        ):
            raise kitpro_repo.PipelineError("direct installation requires an empty mounted target")
    elif output.exists():
        if not marker.is_file():
            raise kitpro_repo.PipelineError(f"refusing to replace unrecognized rootfs: {output}")
        completed_manifest = artifact_root / "rootfs-manifest.json"
        if completed_manifest.is_file():
            existing = kitpro_repo.load_json(completed_manifest)
            validate_rootfs_manifest(existing)
            if existing["stable_generation"] == profile["generation"]:
                return existing
        suffix = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        preserved = output.with_name(f"failed-rootfs-{suffix}")
        if preserved.exists():
            raise kitpro_repo.PipelineError(f"failed-root preservation target exists: {preserved}")
        os.replace(output, preserved)
    output.mkdir(parents=True, exist_ok=True)
    artifact_root.mkdir(parents=True, exist_ok=True)

    build_config = state_root / "rootfs-build-pacman.conf"
    cache = state_root / "rootfs-cache"
    log = state_root / "log/rootfs-pacman.log"
    cache.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.setup_kitpro_keyring(
        PROJECT_ROOT / ".state/client/gnupg",
        PROJECT_ROOT / ".state/dev-keys/public",
    )
    kitpro_repo.render_template(
        PROJECT_ROOT / "config/rootfs-build-pacman.conf.in",
        build_config,
        {
            "CACHE_PATH": str(cache.resolve()),
            "KITPRO_GPG_PATH": str((PROJECT_ROOT / ".state/client/gnupg").resolve()),
            "LOG_PATH": str(log.resolve()),
            "RELEASE": profile["release"],
            "STABLE_GENERATION": str(generation_root.resolve()),
        },
    )
    namespace_option = [] if os.geteuid() == 0 else ["-N"]
    run(
        [
            str(pacstrap_path(state_root)), *namespace_option, "-G", "-M", "-C",
            str(build_config), str(output), *profile["explicit_packages"],
        ]
    )
    output.chmod(0o755)
    write(marker, "KITPro Linux Phase 2 generated root filesystem\n")
    private_key, repositories = configure_rootfs(
        output, profile, generation_manifest["source_epoch"], state_root
    )

    installed = installed_packages(output)
    expected = {
        package["name"]: package
        for repository in generation_manifest["repositories"]
        for package in repository["packages"]
    }
    if installed != {name: package["version"] for name, package in expected.items()}:
        missing = sorted(set(expected) - set(installed))
        extra = sorted(set(installed) - set(expected))
        changed = sorted(name for name in set(installed) & set(expected) if installed[name] != expected[name]["version"])
        raise kitpro_repo.PipelineError(
            f"installed inventory differs from Stable generation: missing={missing}, extra={extra}, changed={changed}"
        )
    kernel = expected[profile["kernel_package"]]
    manifest = {
        "schema_version": 1,
        "kitpro_release": profile["release"],
        "stable_generation": profile["generation"],
        "architecture": profile["architecture"],
        "explicit_packages": profile["explicit_packages"],
        "resolved_package_count": len(installed),
        "packages": [
            {"name": name, "version": installed[name], "sha256": expected[name]["sha256"]}
            for name in sorted(installed)
        ],
        "kernel": {
            "package": profile["kernel_package"],
            "version": kernel["version"],
            "image_sha256": kitpro_repo.sha256_file(output / "boot/vmlinuz-linux-lts"),
        },
        "initramfs": {
            "tool": profile["initramfs_tool"],
            "sha256": kitpro_repo.sha256_file(output / "boot/initramfs-linux-lts.img"),
            "configuration_sha256": kitpro_repo.sha256_file(output / "etc/mkinitcpio.conf"),
        },
        "bootloader": profile["bootloader"],
        "filesystem": profile["filesystem"],
        "root_filesystem_uuid": None,
        "network": {
            "manager": "systemd-networkd",
            "resolver": "systemd-resolved",
            "default_profile": "dhcp",
            "static_test_profile": "configured by qualification fixture",
        },
        "ssh": {
            "enabled_for_test_profile": profile.get("enable_sshd", True),
            "administrator": profile["administrator"],
            "private_key_path": str(private_key.relative_to(PROJECT_ROOT)) if private_key else None,
            "root_login": False,
            "password_authentication": False,
        },
        "nftables": {"input_policy": "drop", "ssh_allowed": True},
        "enabled_systemd_units": [
            "systemd-networkd.service", "systemd-resolved.service",
            "systemd-timesyncd.service", "nftables.service",
            *(["sshd.service"] if profile.get("enable_sshd", True) else []),
            "serial-getty@ttyS0.service",
        ],
        "build_timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "build_tools": {
            "pacman": command_version(["pacman", "--version"]),
            "pacstrap": pacstrap_version(state_root),
            "systemd": command_version(["systemctl", "--version"]),
            "mkinitcpio": f"mkinitcpio {expected['mkinitcpio']['version']} (guest)",
        },
        "rootfs_size_bytes": directory_size(output),
        "repository": {
            "enabled": repositories,
            "generation_manifest_sha256": kitpro_repo.sha256_file(generation_root / "manifest.json"),
            "signature_policy": "Required DatabaseRequired TrustedOnly",
        },
        "disk_image": {"path": None, "size_bytes": None, "sha256": None},
        "test_results": {"status": "not_run", "checks": {}},
    }
    validate_rootfs_manifest(manifest)
    kitpro_repo.atomic_write_json(artifact_root / "rootfs-manifest.json", manifest)
    return manifest


def mtools_path(state_root: Path) -> Path | None:
    direct = shutil.which("mcopy")
    if direct:
        return Path(direct).parent
    for root in (state_root / "vm-tools", state_root / "host-tools"):
        local = root / "usr/bin/mcopy"
        if local.is_file():
            return local.parent
    return None


def build_image(
    rootfs: Path,
    image: Path,
    artifact_root: Path,
    state_root: Path,
) -> dict[str, Any]:
    manifest_path = artifact_root / "rootfs-manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    validate_rootfs_manifest(manifest)
    validate_rootfs_preflight(rootfs)
    if image.exists():
        image.unlink()
    image.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    mtools = mtools_path(state_root)
    if mtools:
        environment["PATH"] = f"{mtools}:{environment['PATH']}"
    environment["SYSTEMD_LOG_TARGET"] = "console"
    completed = subprocess.run(
        [
            "unshare", "--fork", "--pid", "--mount", "--map-auto", "--map-root-user",
            "systemd-repart", "--dry-run=no", "--offline=yes", "--empty=create", "--size=3400M",
            f"--definitions={PROJECT_ROOT / 'config/repart.d'}", f"--copy-source={rootfs}",
            "--json=short", str(image),
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"systemd-repart failed ({completed.returncode})\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    table = run(["parted", "-sm", str(image), "unit", "B", "print"]).stdout
    root_line = next((line for line in table.splitlines() if ":KITPRO_ROOT:" in line), None)
    if not root_line:
        raise kitpro_repo.PipelineError("image has no KITPRO_ROOT partition")
    root_offset = root_line.split(":")[1].removesuffix("B")
    root_uuid = run(["blkid", "-p", "-o", "value", "-s", "UUID", "-O", root_offset, str(image)]).stdout.strip()
    if not root_uuid:
        raise kitpro_repo.PipelineError("root filesystem UUID is unavailable")
    manifest["root_filesystem_uuid"] = root_uuid
    manifest["disk_image"] = {
        "path": str(image.relative_to(PROJECT_ROOT)),
        "size_bytes": image.stat().st_size,
        "sha256": kitpro_repo.sha256_file(image),
        "partition_table": "gpt",
        "esp_partition_uuid": "ba32d0a7-10bd-48da-b76a-8133d5ad55d5",
        "root_partition_uuid": "75b47216-f34a-4fd5-a6c5-d5254c04a731",
        "partition_table_report": table,
        "systemd_repart_report": json.loads(completed.stdout),
    }
    validate_rootfs_manifest(manifest)
    kitpro_repo.atomic_write_json(manifest_path, manifest)
    return manifest


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    rootfs = subcommands.add_parser("build-rootfs")
    rootfs.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    rootfs.add_argument("--repo-root", type=Path, default=DEFAULT_REPO_ROOT)
    rootfs.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    rootfs.add_argument("--output", type=Path, default=DEFAULT_STATE_ROOT / "rootfs")
    rootfs.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    image = subcommands.add_parser("build-image")
    image.add_argument("--rootfs", type=Path, default=DEFAULT_STATE_ROOT / "rootfs")
    image.add_argument("--image", type=Path, default=DEFAULT_STATE_ROOT / "kitpro-linux-phase2.raw")
    image.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    image.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    vm_tools = subcommands.add_parser("bootstrap-vm-tools")
    vm_tools.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    vm_tools.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    pacstrap = subcommands.add_parser("bootstrap-pacstrap")
    pacstrap.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    pacstrap.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACT_ROOT)
    verify = subcommands.add_parser("validate-manifest")
    verify.add_argument("path", type=Path)
    return command


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "build-rootfs":
            result = build_rootfs(
                arguments.profile.resolve(), arguments.repo_root.resolve(), arguments.state_root.resolve(),
                arguments.output.resolve(), arguments.artifacts.resolve(),
            )
        elif arguments.command == "build-image":
            result = build_image(
                arguments.rootfs.resolve(), arguments.image.resolve(), arguments.artifacts.resolve(),
                arguments.state_root.resolve(),
            )
        elif arguments.command == "bootstrap-vm-tools":
            result = bootstrap_vm_tools(arguments.state_root.resolve(), arguments.artifacts.resolve())
        elif arguments.command == "bootstrap-pacstrap":
            result = bootstrap_pacstrap(arguments.state_root.resolve(), arguments.artifacts.resolve())
        else:
            result = kitpro_repo.load_json(arguments.path.resolve())
            validate_rootfs_manifest(result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except kitpro_repo.PipelineError as error:
        print(f"error: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
