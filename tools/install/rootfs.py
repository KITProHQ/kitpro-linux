"""Reuse the Phase 2 rootfs builder and apply one Phase 3 install plan."""

from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Callable

from tools import kitpro_phase2, kitpro_repo
from tools.install.model import InstallSpec
from tools.install.passwords import configure_account_password
from tools.install.render import fstab, loader_entry, networkd, nftables, sshd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_ROOT = PROJECT_ROOT / ".state/phase3"
BASE_ROOTFS = STATE_ROOT / "base-rootfs"
BASE_ARTIFACTS = STATE_ROOT / "base-rootfs-artifacts"
PROFILE = PROJECT_ROOT / "config/install-rootfs-profile.json"
PHASE2_STATE = PROJECT_ROOT / ".state/phase2"
KERNEL_RUNTIME = PROJECT_ROOT / "runtime/kernel-lifecycle"
KERNEL_BOOT_VALIDATE = PROJECT_ROOT / "runtime/kernel-boot-validate"
KERNEL_STATUS = PROJECT_ROOT / "runtime/kitpro-kernel-status"
SYSTEM_HEALTH_RUNTIME = PROJECT_ROOT / "runtime/system-health"
SYSTEM_HEALTH = PROJECT_ROOT / "runtime/kitpro-health"
SUPPORT_BUNDLE_RUNTIME = PROJECT_ROOT / "runtime/support-bundle"
SUPPORT_BUNDLE = PROJECT_ROOT / "runtime/kitpro-support-bundle"
SUPPORT_INSPECTION_MODULES = (
    PROJECT_ROOT / "tools/__init__.py",
    PROJECT_ROOT / "tools/system_health.py",
    PROJECT_ROOT / "tools/support_bundle.py",
    PROJECT_ROOT / "tools/support_bundle_inspect.py",
)
REPOSITORY_POLICY = PROJECT_ROOT / "runtime/repository-policy.conf"


def _write(path: Path, value: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write(path, value.encode(), mode)


def _copy_phase2_install_tools() -> None:
    if shutil.which("pacstrap") and shutil.which("arch-chroot"):
        return
    destination_host_tools = STATE_ROOT / "host-tools"
    destination_tools = destination_host_tools / "usr/bin"
    destination_packages = STATE_ROOT / "host-packages"
    if (destination_tools / "pacstrap").is_file() and (destination_tools / "arch-chroot").is_file():
        return
    source_host_tools = PHASE2_STATE / "host-tools"
    sources = source_host_tools / "usr/bin"
    packages = PHASE2_STATE / "host-packages"
    required = [sources / "pacstrap", sources / "arch-chroot"]
    if any(not path.is_file() for path in required):
        kitpro_phase2.bootstrap_pacstrap(STATE_ROOT, BASE_ARTIFACTS)
        return
    shutil.copytree(source_host_tools, destination_host_tools, dirs_exist_ok=True)
    destination_packages.mkdir(parents=True, exist_ok=True)
    for source in packages.glob("arch-install-scripts-31-2-any.pkg.tar.zst*"):
        shutil.copy2(source, destination_packages / source.name)


def prepare_base_rootfs(plan: dict[str, Any]) -> dict[str, Any]:
    profile = kitpro_repo.load_json(PROFILE)
    if profile["release"] != plan["release"] or profile["generation"] != plan["repository_generation"]:
        raise kitpro_repo.PipelineError("Root filesystem profile does not match the install plan")
    _copy_phase2_install_tools()
    return kitpro_phase2.build_rootfs(
        PROFILE,
        PROJECT_ROOT / "repo",
        STATE_ROOT,
        BASE_ROOTFS,
        BASE_ARTIFACTS,
    )


def validate_install_source(plan: dict[str, Any]) -> None:
    """Revalidate all offline inputs before a direct install can erase a disk."""
    profile = kitpro_repo.load_json(PROFILE)
    if (profile["release"] != plan["release"]
            or profile["generation"] != plan["repository_generation"]
            or kitpro_repo.sha256_file(PROFILE) != plan["rootfs"]["profile_sha256"]):
        raise kitpro_repo.PipelineError("installation profile changed after planning")
    if profile["release"] == "1.0":
        from tools.install import production
        generation_root, _ = production.verify(profile["generation"], PROJECT_ROOT / "repo")
        if kitpro_repo.sha256_file(generation_root / "manifest.json") != plan["repository"]["generation_manifest_sha256"]:
            raise kitpro_repo.PipelineError("production generation changed after planning")
        return
    generation_root, manifest = kitpro_phase2.generation(profile, PROJECT_ROOT / "repo")
    if kitpro_repo.sha256_file(generation_root / "manifest.json") != plan["repository"]["generation_manifest_sha256"]:
        raise kitpro_repo.PipelineError("installation generation changed after planning")
    kitpro_repo.verify_manifest_artifacts(
        manifest, PROJECT_ROOT / "repo", generation_root, PROJECT_ROOT / ".state/dev-keys"
    )


def _firewall_check_command(config: Path) -> list[str]:
    # A rootless worker may already have mapped root privileges, and Linux
    # refuses a nested user namespace from its chroot. Still create a fresh
    # network namespace so validation cannot affect the worker firewall.
    mapping = Path("/proc/self/uid_map").read_text().splitlines()
    mapped_root = os.geteuid() == 0 and any(
        fields[0] == "0" and fields[1] != "0"
        for line in mapping if len(fields := line.split()) == 3
    )
    user_options = [] if mapped_root else ["--user", "--map-root-user"]
    return ["unshare", *user_options, "--net", "nft", "-c", "-f", str(config)]


def _configure_locale(root: Path, locale: str, source_epoch: int) -> None:
    _write(root / "etc/locale.conf", f"LANG={locale}\n")
    if locale == "C.UTF-8":
        return
    locale_gen = root / "etc/locale.gen"
    content = locale_gen.read_text()
    changed = re.sub(r"^#\s*(en_US\.UTF-8 UTF-8)\s*$", r"\1", content, flags=re.MULTILINE)
    if changed == content and "en_US.UTF-8 UTF-8" not in content:
        raise kitpro_repo.PipelineError("guest locale inventory lacks en_US.UTF-8")
    _write(locale_gen, changed)
    kitpro_phase2.run_in_root_namespace(
        root,
        ["/usr/bin/env", f"SOURCE_DATE_EPOCH={source_epoch}", "locale-gen"],
        STATE_ROOT,
    )


def _configure_account(
    root: Path,
    spec: InstallSpec,
    administrator_password: str | None = None,
) -> None:
    username = spec.administrator.username
    _write(
        root / "usr/lib/sysusers.d/kitpro-installer-admin.conf",
        f"g {username} 1000\n"
        f"u {username} 1000:1000 'KITPro administrator' /home/{username} /bin/bash\n"
        f"m {username} wheel\n",
    )
    kitpro_phase2.run(["systemd-sysusers", f"--root={root}"])
    if not any(line.startswith(f"{username}:") for line in (root / "etc/passwd").read_text().splitlines()):
        raise kitpro_repo.PipelineError("administrator account creation failed")
    configure_account_password(
        root,
        username,
        plaintext=administrator_password,
        password_hash=spec.administrator.password_hash,
    )
    home = root / "home" / username
    ssh_directory = home / ".ssh"
    ssh_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if spec.administrator.ssh_authorized_keys:
        _write(
            ssh_directory / "authorized_keys",
            "\n".join(spec.administrator.ssh_authorized_keys) + "\n",
            0o600,
        )
    _write(
        root / "etc/sudoers.d/10-kitpro-installer-admin",
        "%wheel ALL=(ALL:ALL) ALL\n",
        0o440,
    )
    if os.geteuid() == 0:
        kitpro_phase2.run(["chown", "-R", "1000:1000", str(home)])
    else:
        kitpro_phase2.run(
            [
                "unshare", "--fork", "--pid", "--mount", "--map-auto", "--map-root-user",
                "chown", "-R", "1000:1000", str(home),
            ]
        )


def _configure_services(root: Path, spec: InstallSpec) -> list[str]:
    _write(
        root
        / "etc/systemd/system/systemd-networkd-wait-online.service.d"
        / "10-kitpro-any-interface.conf",
        "[Service]\n"
        "ExecStart=\n"
        "ExecStart=/usr/lib/systemd/systemd-networkd-wait-online --any --ipv4 --timeout=30\n",
    )
    enabled = [
        "systemd-networkd.service", "systemd-resolved.service", "systemd-timesyncd.service",
        "nftables.service", "getty@tty1.service", "serial-getty@ttyS0.service",
        "kitpro-install-first-boot-validation.service",
        "kitpro-kernel-boot-validation.service",
    ]
    if spec.ssh.enabled:
        enabled.append("sshd.service")
    kitpro_phase2.run(["systemctl", f"--root={root}", "enable", *enabled])
    if not spec.ssh.enabled:
        kitpro_phase2.run(["systemctl", f"--root={root}", "disable", "sshd.service"])
    kitpro_phase2.run(["systemctl", f"--root={root}", "set-default", "multi-user.target"])
    return enabled


def _configure_first_boot_validation(
    root: Path,
    spec: InstallSpec,
    package_count: int,
) -> None:
    username = spec.administrator.username
    repository_path = (
        "https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/"
        if spec.release.name == "1.0" else f"/{spec.release.generation}/"
    )
    network_check = "ip -4 -o address show scope global dynamic | grep -q ."
    if spec.network.mode == "static":
        network_check = (
            "ip -4 -o address show scope global "
            f"| grep -Fq ' {spec.network.address}/{spec.network.prefix} '\n"
            f"ip -4 route show default | grep -Fq 'via {spec.network.gateway}'\n"
            f"resolvectl dns | grep -Fq '{spec.network.dns[0]}'"
        )
    ssh_check = "systemctl is-active --quiet sshd\nnft list ruleset | grep -q 'tcp dport 22'"
    if not spec.ssh.enabled:
        ssh_check = (
            "! systemctl is-enabled --quiet sshd\n"
            "! ss -ltnH | awk '{{print $4}}' | grep -Eq '(^|:)22$'\n"
            "! nft list ruleset | grep -q 'tcp dport 22'"
        )
    script = f"""#!/usr/bin/bash
set -euo pipefail
for attempt in {{1..30}}; do
    if networkctl --no-pager --no-legend | grep -q 'routable'; then
        break
    fi
    sleep 1
done
networkctl --no-pager --no-legend | grep -q 'routable'
systemctl is-active --quiet systemd-networkd systemd-resolved systemd-timesyncd
test -z "$(systemctl --failed --no-legend)"
test -d /var/log/journal
journalctl -b --no-pager -n 1 >/dev/null
test "$(systemctl show nftables -p Result --value)" = success
nft list ruleset | grep -q 'policy drop'
{network_check}
test "$(readlink /etc/resolv.conf)" = ../run/systemd/resolve/stub-resolv.conf
{ssh_check}
id {username}
! runuser -u {username} -- sudo -n id -u
grep -q '^%wheel ALL=(ALL:ALL) ALL$' /etc/sudoers.d/10-kitpro-installer-admin
! grep -R '^[[:space:]]*[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d
grep -q '^ID=kitpro-linux$' /etc/os-release
grep -q '"generation": "{spec.release.generation}"' /etc/kitpro-linux-release.json
grep -Fq '{repository_path}' /etc/pacman.conf
! grep -Eq '^\\[(core|extra|.*testing|.*staging|multilib|aur)\\]' /etc/pacman.conf
test "$(pacman -Qq | wc -l)" -eq {package_count}
install -d -m755 /var/lib/kitpro-linux
printf '%s\n' passed > /var/lib/kitpro-linux/first-boot-validation
printf '%s\n' KITPRO_INSTALL_FIRST_BOOT_OK > /dev/ttyS0
"""
    _write(root / "usr/lib/kitpro-linux/install-first-boot-validate", script, 0o755)
    _write(
        root / "usr/lib/systemd/system/kitpro-install-first-boot-validation.service",
        "[Unit]\n"
        "Description=Validate the first boot of a KITPro Linux installation\n"
        "ConditionPathExists=!/var/lib/kitpro-linux/first-boot-validation\n"
        "After=network-online.target nftables.service\n"
        "Wants=network-online.target\n"
        "Before=multi-user.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/lib/kitpro-linux/install-first-boot-validate\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
    )


def _configure_kernel_boot_validation(root: Path) -> None:
    destination = root / "usr/lib/kitpro-linux/kernel-boot-validate"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(KERNEL_BOOT_VALIDATE, destination)
    destination.chmod(0o755)
    _write(
        root / "usr/lib/systemd/system/kitpro-kernel-boot-validation.service",
        "[Unit]\n"
        "Description=Validate the active KITPro kernel before recording a successful boot\n"
        "After=kitpro-install-first-boot-validation.service network-online.target nftables.service\n"
        "Wants=network-online.target\n"
        "Before=multi-user.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "ExecStart=/usr/lib/kitpro-linux/kernel-boot-validate\n"
        "RemainAfterExit=yes\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
    )


def _configure_production_identity(root: Path) -> None:
    kitpro_phase2.copy(
        PROJECT_ROOT / "tools/production_identity.py",
        root / "usr/lib/kitpro-linux/repository-identity",
        0o755,
    )
    _write(
        root / "usr/share/libalpm/hooks/90-kitpro-repository-identity.hook",
        "[Trigger]\nType = Package\nOperation = Install\nOperation = Upgrade\n"
        "Operation = Remove\nTarget = *\n\n[Action]\n"
        "Description = Recording the verified production generation...\n"
        "When = PostTransaction\nExec = /usr/lib/kitpro-linux/repository-identity\n",
    )


def configure_staging_rootfs(
    root: Path,
    spec: InstallSpec,
    plan: dict[str, Any],
    source_epoch: int,
    receipt: dict[str, Any],
    kernel_package_version: str,
    stage_callback: Callable[[str], None] | None = None,
    administrator_password: str | None = None,
) -> dict[str, Any]:
    hostname = spec.system.hostname
    _write(root / "etc/hostname", hostname + "\n")
    _write(
        root / "etc/hosts",
        f"127.0.0.1 localhost\n::1 localhost\n127.0.1.1 {hostname}\n",
    )
    timezone = root / "usr/share/zoneinfo" / spec.system.timezone
    if not timezone.is_file():
        raise kitpro_repo.PipelineError(f"timezone is unavailable in the rootfs: {spec.system.timezone}")
    localtime = root / "etc/localtime"
    localtime.unlink(missing_ok=True)
    os.symlink("../usr/share/zoneinfo/" + spec.system.timezone, localtime)
    _configure_locale(root, spec.system.locale, source_epoch)

    network_root = root / "etc/systemd/network"
    for path in network_root.glob("20-wired-*.network*"):
        path.unlink()
    _write(network_root / "20-kitpro.network", networkd(spec))
    resolv = root / "etc/resolv.conf"
    resolv.unlink(missing_ok=True)
    os.symlink("../run/systemd/resolve/stub-resolv.conf", resolv)

    _configure_account(root, spec, administrator_password)
    _write(root / "etc/ssh/sshd_config.d/10-kitpro-server.conf", sshd(spec))
    _write(root / "etc/nftables.conf", nftables(spec), 0o755)
    kitpro_phase2.run(_firewall_check_command(root / "etc/nftables.conf"))
    _configure_first_boot_validation(root, spec, plan["repository"]["package_count"])
    _configure_kernel_boot_validation(root)
    enabled = _configure_services(root, spec)

    if stage_callback:
        stage_callback("boot_setup")
    esp_uuid = plan["partition_table"]["esp"]["partition_uuid"]
    root_uuid = plan["partition_table"]["root"]["partition_uuid"]
    _write(root / "etc/fstab", fstab(esp_uuid, root_uuid))
    _write(
        root / "etc/kitpro-installation.json",
        kitpro_repo.canonical_json_bytes(
            {
                "schema_version": 1,
                "installer_version": plan["installer_version"],
                "install_spec_sha256": plan["install_spec_sha256"],
                "install_plan_sha256": plan["plan_sha256"],
                "release": plan["release"],
                "generation": plan["repository_generation"],
            }
        ).decode(),
    )
    kitpro_repo.atomic_write_json(root / "var/lib/kitpro-linux/install-receipt.json", receipt)
    kitpro_phase2.run_in_root_namespace(root, ["ssh-keygen", "-A"], STATE_ROOT)
    kitpro_phase2.run_in_root_namespace(root, ["sshd", "-t"], STATE_ROOT)
    kitpro_phase2.run_in_root_namespace(
        root,
        [
            "/usr/bin/env",
            f"SOURCE_DATE_EPOCH={source_epoch}",
            "TMPDIR=/tmp",
            "mkinitcpio",
            "-P",
        ],
        STATE_ROOT,
    )
    runtime = root / "usr/lib/kitpro-linux/kernel-lifecycle"
    kitpro_phase2.copy(KERNEL_RUNTIME, runtime, 0o755)
    kitpro_phase2.copy(KERNEL_STATUS, root / "usr/bin/kitpro-kernel-status", 0o755)
    kitpro_phase2.copy(
        SYSTEM_HEALTH_RUNTIME,
        root / "usr/lib/kitpro-linux/system-health",
        0o755,
    )
    kitpro_phase2.copy(SYSTEM_HEALTH, root / "usr/bin/kitpro-health", 0o755)
    kitpro_phase2.copy(
        SUPPORT_BUNDLE_RUNTIME,
        root / "usr/lib/kitpro-linux/support-bundle",
        0o755,
    )
    kitpro_phase2.copy(
        SUPPORT_BUNDLE,
        root / "usr/bin/kitpro-support-bundle",
        0o755,
    )
    inspection_package = root / "usr/lib/kitpro-linux/python/tools"
    for module in SUPPORT_INSPECTION_MODULES:
        kitpro_phase2.copy(module, inspection_package / module.name, 0o644)
    kitpro_phase2.copy(
        REPOSITORY_POLICY,
        root / "usr/lib/kitpro-linux/repository-policy.conf",
        0o644,
    )
    if spec.release.name == "1.0":
        _configure_production_identity(root)
    _write(
        root / "usr/share/libalpm/hooks/50-kitpro-kernel-preserve.hook",
        "[Trigger]\nType = Package\nOperation = Upgrade\nTarget = linux-lts\n\n"
        "[Action]\nDescription = Preserving the KITPro previous known-good kernel...\n"
        "When = PreTransaction\nExec = /usr/lib/kitpro-linux/kernel-lifecycle stage\n",
    )
    _write(
        root / "usr/share/libalpm/hooks/95-kitpro-kernel-activate.hook",
        "[Trigger]\nType = Package\nOperation = Upgrade\nTarget = linux-lts\n\n"
        "[Action]\nDescription = Activating the KITPro kernel candidate...\n"
        "When = PostTransaction\nExec = /usr/lib/kitpro-linux/kernel-lifecycle activate\n",
    )
    kernel_releases = sorted(
        path.name
        for path in (root / "usr/lib/modules").iterdir()
        if path.is_dir()
        and (path / "pkgbase").is_file()
        and (path / "pkgbase").read_text().strip() == "linux-lts"
        and (path / "vmlinuz").is_file()
    )
    if len(kernel_releases) != 1:
        raise kitpro_repo.PipelineError(
            f"fresh install requires exactly one linux-lts module tree: {kernel_releases}"
        )
    kitpro_phase2.run(
        [
            str(runtime), "--root", str(root), "initialize",
            "--package-version", kernel_package_version,
            "--generation", spec.release.generation,
            "--root-partuuid", root_uuid,
            "--kernel-release", kernel_releases[0],
        ]
    )
    validate_configured_rootfs(root, spec, plan)
    return {
        "enabled_systemd_units": enabled,
        "kernel_sha256": kitpro_repo.sha256_file(root / "boot/vmlinuz-linux-lts"),
        "initramfs_sha256": kitpro_repo.sha256_file(root / "boot/initramfs-linux-lts.img"),
        "network_config_sha256": kitpro_repo.sha256_file(network_root / "20-kitpro.network"),
        "nftables_config_sha256": kitpro_repo.sha256_file(root / "etc/nftables.conf"),
        "sshd_config_sha256": kitpro_repo.sha256_file(
            root / "etc/ssh/sshd_config.d/10-kitpro-server.conf"
        ),
    }


def validate_configured_rootfs(root: Path, spec: InstallSpec, plan: dict[str, Any]) -> None:
    if (root / "etc/hostname").read_text().strip() != spec.system.hostname:
        raise kitpro_repo.PipelineError("installed hostname does not match the plan")
    if not (root / "etc/localtime").is_symlink():
        raise kitpro_repo.PipelineError("installed timezone link is missing")
    sudoers = root / "etc/sudoers.d/10-kitpro-installer-admin"
    if not sudoers.is_file() or sudoers.read_text() != "%wheel ALL=(ALL:ALL) ALL\n":
        raise kitpro_repo.PipelineError("installed sudo policy must require wheel authentication")
    network = (root / "etc/systemd/network/20-kitpro.network").read_text()
    if spec.network.mode == "dhcp" and "DHCP=yes" not in network:
        raise kitpro_repo.PipelineError("installed DHCP configuration is invalid")
    if spec.network.mode == "static" and not all(
        value in network for value in ("Address=", "Gateway=", "DNS=")
    ):
        raise kitpro_repo.PipelineError("installed static network configuration is invalid")
    wait_online = (
        root
        / "etc/systemd/system/systemd-networkd-wait-online.service.d"
        / "10-kitpro-any-interface.conf"
    )
    expected_wait = (
        "ExecStart=/usr/lib/systemd/systemd-networkd-wait-online "
        "--any --ipv4 --timeout=30"
    )
    if not wait_online.is_file() or expected_wait not in wait_online.read_text():
        raise kitpro_repo.PipelineError("installed network readiness policy is invalid")
    firewall = (root / "etc/nftables.conf").read_text()
    if not all(value in firewall for value in ("policy drop", 'iifname "lo" accept', "established,related")):
        raise kitpro_repo.PipelineError("installed nftables configuration is invalid")
    if ("tcp dport 22" in firewall) != spec.ssh.enabled:
        raise kitpro_repo.PipelineError("installed firewall and SSH policy disagree")
    ssh_configuration = (root / "etc/ssh/sshd_config.d/10-kitpro-server.conf").read_text()
    required_ssh = (
        "PermitRootLogin no", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "AuthenticationMethods publickey",
    )
    if any(value not in ssh_configuration for value in required_ssh):
        raise kitpro_repo.PipelineError("installed SSH configuration is invalid")
    entry = (root / "efi/loader/entries/kitpro-linux.conf").read_text()
    expected_root = plan["partition_table"]["root"]["partition_uuid"]
    if f"root=PARTUUID={expected_root}" not in entry:
        raise kitpro_repo.PipelineError("installed boot entry has the wrong root partition")
    if "console=ttyS0,115200n8 console=tty0" not in entry:
        raise kitpro_repo.PipelineError("installed boot entry lacks dual-console policy")
    if "systemd.debug_shell" in entry:
        raise kitpro_repo.PipelineError("installed boot entry enables the systemd debug shell")
    compatibility_entry = root / "efi/loader/entries/kitpro-linux-compatibility.conf"
    if not compatibility_entry.is_file() or "nomodeset" not in compatibility_entry.read_text():
        raise kitpro_repo.PipelineError("installed compatibility graphics entry is missing")
    repositories = kitpro_phase2.validate_repository_isolation(root / "etc/pacman.conf")
    if repositories != [f"kitpro-{spec.release.name}-core"]:
        raise kitpro_repo.PipelineError("installed repository name does not match the release")
    pacman = (root / "etc/pacman.conf").read_text()
    if spec.release.name == "1.0":
        from tools.production_repository import production_pacman_config
        if pacman != production_pacman_config():
            raise kitpro_repo.PipelineError("production repository configuration differs from canonical current")
    elif spec.release.generation not in pacman or "/current/" in pacman:
        raise kitpro_repo.PipelineError("installed repository is not pinned to an immutable generation")
    status = root / "usr/bin/kitpro-kernel-status"
    if not status.is_file() or not os.access(status, os.X_OK):
        raise kitpro_repo.PipelineError("installed kernel status command is missing or not executable")
    health = root / "usr/bin/kitpro-health"
    if not health.is_file() or not os.access(health, os.X_OK):
        raise kitpro_repo.PipelineError("installed system health command is missing or not executable")
    support = root / "usr/bin/kitpro-support-bundle"
    if not support.is_file() or not os.access(support, os.X_OK):
        raise kitpro_repo.PipelineError("installed support bundle command is missing or not executable")
    inspector = root / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py"
    if not inspector.is_file():
        raise kitpro_repo.PipelineError("installed support bundle inspection runtime is missing")


def _copy_base_rootfs(destination: Path) -> None:
    temporarily_readable: list[tuple[Path, int]] = []
    for source in BASE_ROOTFS.rglob("*"):
        if source.is_file() and not os.access(source, os.R_OK):
            mode = stat.S_IMODE(source.stat().st_mode)
            source.chmod(mode | stat.S_IRUSR)
            temporarily_readable.append((source, mode))
    try:
        kitpro_phase2.run(
            ["cp", "-a", "--reflink=auto", str(BASE_ROOTFS) + "/.", str(destination)]
        )
    finally:
        for source, mode in temporarily_readable:
            source.chmod(mode)
            copied = destination / source.relative_to(BASE_ROOTFS)
            if copied.exists():
                copied.chmod(mode)


def stage_rootfs(
    spec: InstallSpec,
    plan: dict[str, Any],
    receipt: dict[str, Any],
    stage_callback: Callable[[str], None] | None = None,
    administrator_password: str | None = None,
    *,
    mounted_target: Path | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    if spec.sha256() != plan["install_spec_sha256"]:
        raise kitpro_repo.PipelineError("install specification does not match the install plan")
    if mounted_target is None:
        if spec.release.name == "1.0":
            raise kitpro_repo.PipelineError("production installation requires direct mounted deployment")
        base_manifest = prepare_base_rootfs(plan)
    else:
        profile = kitpro_repo.load_json(PROFILE)
        if profile["release"] != plan["release"] or profile["generation"] != plan["repository_generation"]:
            raise kitpro_repo.PipelineError("rootfs profile does not match the install plan")
        # Package cache, logs and any tool scratch live on the target disk.
        # pacstrap/libalpm extract the signed packages directly into that target.
        disk_state = mounted_target / ".kitpro-install-work"
        disk_state.mkdir(mode=0o700)
        if spec.release.name == "1.0":
            from tools.install import production
            base_manifest = production.deploy(
                profile, PROJECT_ROOT / "repo", mounted_target, disk_state, BASE_ARTIFACTS
            )
        else:
            base_manifest = kitpro_phase2.build_rootfs(
                PROFILE, PROJECT_ROOT / "repo", disk_state, mounted_target,
                BASE_ARTIFACTS, mounted_target=True,
            )
    base_manifest_path = BASE_ARTIFACTS / "rootfs-manifest.json"
    work = STATE_ROOT / "work" / plan["plan_sha256"]
    root = mounted_target if mounted_target is not None else work / "rootfs"
    if mounted_target is None and root.exists():
        raise kitpro_repo.PipelineError(
            f"partial staging root already exists for this plan: {root}"
        )
    if mounted_target is None:
        root.parent.mkdir(parents=True, exist_ok=True)
        _copy_base_rootfs(root)
    if stage_callback:
        stage_callback("configuration")
    generation_manifest = kitpro_repo.load_json(
        PROJECT_ROOT / "repo/stable" / spec.release.name / spec.release.generation / "manifest.json"
    )
    configuration = configure_staging_rootfs(
        root,
        spec,
        plan,
        (generation_manifest["source"]["epoch"] if spec.release.name == "1.0"
         else generation_manifest["source_epoch"]),
        receipt,
        base_manifest["kernel"]["version"],
        stage_callback,
        administrator_password,
    )
    configuration["install_receipt_sha256"] = kitpro_repo.sha256_file(
        root / "var/lib/kitpro-linux/install-receipt.json"
    )
    configuration["base_rootfs_manifest_sha256"] = kitpro_repo.sha256_file(base_manifest_path)
    configuration["package_count"] = base_manifest["resolved_package_count"]
    if mounted_target is not None:
        shutil.rmtree(root / ".kitpro-install-work")
        (root / ".kitpro-phase2-build-root").unlink(missing_ok=True)
    return root, base_manifest, configuration
