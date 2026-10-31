from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_install_schema import valid_document
from tools import kitpro_repo
from tools.install import rootfs as install_rootfs
from tools.install.model import parse_spec
from tools.install.rootfs import validate_configured_rootfs
from tools.install.render import fstab_from_plan, loader_entry, networkd, nftables


def plan() -> dict[str, object]:
    return {
        "partition_table": {
            "esp": {"partition_uuid": "esp-id"},
            "root": {"partition_uuid": "root-id"},
        }
    }


class ConfiguredRootfsValidationTests(unittest.TestCase):
    def test_production_repository_hook_selection_uses_profile_trust(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            profile = Path(name) / "profile.json"
            profile.write_text('{"trust":"production-signed"}\n')
            with mock.patch.object(install_rootfs, "PROFILE", profile):
                self.assertTrue(install_rootfs._production_signed_profile())

    def test_linux_1_1_production_trust_uses_bounded_production_deployer(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            profile = Path(name) / "profile.json"
            profile.write_text('{"trust":"production-signed"}\n')
            document = valid_document()
            document["release"] = {"name": "1.1", "generation": "1.1-g0001"}
            with mock.patch.object(install_rootfs, "PROFILE", profile):
                self.assertTrue(
                    install_rootfs._requires_production_deployment(parse_spec(document))
                )

    def test_linux_1_1_development_trust_does_not_use_production_deployer(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            profile = Path(name) / "profile.json"
            profile.write_text('{"trust":"development"}\n')
            document = valid_document()
            document["release"] = {"name": "1.1", "generation": "1.1-g0001"}
            with mock.patch.object(install_rootfs, "PROFILE", profile):
                self.assertFalse(
                    install_rootfs._requires_production_deployment(parse_spec(document))
                )

    def test_linux_1_1_production_repository_accepts_only_canonical_current(self) -> None:
        from tools.install import production

        canonical = production.pacman_config("1.1-g0001")
        install_rootfs._validate_installed_repository(
            canonical, "1.1", "1.1-g0001", True
        )
        with self.assertRaisesRegex(
            kitpro_repo.PipelineError, "canonical current"
        ):
            install_rootfs._validate_installed_repository(
                canonical.replace("/current/", "/1.1-g0001/"),
                "1.1",
                "1.1-g0001",
                True,
            )

    def test_first_boot_validation_accepts_linux_1_1_production_current(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "root"
            profile = Path(name) / "profile.json"
            profile.write_text('{"trust":"production-signed"}\n')
            document = valid_document()
            document["release"] = {"name": "1.1", "generation": "1.1-g0001"}
            with mock.patch.object(install_rootfs, "PROFILE", profile):
                install_rootfs._configure_first_boot_validation(
                    root, parse_spec(document), 199
                )
            script = (root / "usr/lib/kitpro-linux/install-first-boot-validate").read_text()
            self.assertIn(
                "https://repo.kitpro.us/kitpro-linux/stable/1.1/current/core/os/",
                script,
            )
            self.assertNotIn("/1.1-g0001/", script)

    def test_development_deployment_allows_only_planned_mounted_directories(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            home = root / "home"
            home.mkdir()

            def is_mount(path: Path) -> bool:
                return path in {root, home}

            with mock.patch.object(Path, "is_mount", is_mount):
                install_rootfs.kitpro_phase2.validate_empty_mounted_target(
                    root, frozenset({"home"})
                )
                (root / "unexpected").mkdir()
                with self.assertRaisesRegex(kitpro_repo.PipelineError, "empty mounted target"):
                    install_rootfs.kitpro_phase2.validate_empty_mounted_target(
                        root, frozenset({"home"})
                    )

    def test_manual_partition_mounts_are_allowed_during_rootfs_deployment(self) -> None:
        installation_plan = {
            "partition_table": {
                "partitions": [
                    {"role": "esp", "mount_point": "/efi"},
                    {"role": "root", "mount_point": "/"},
                    {"role": "home", "mount_point": "/home"},
                    {"role": "var", "mount_point": "/var"},
                    {"role": "srv", "mount_point": "/srv"},
                    {"role": "swap", "mount_point": None},
                ],
                "subvolumes": [
                    {"name": "@", "mount_point": "/"},
                    {"name": "@snapshots", "mount_point": "/.snapshots"},
                ],
            }
        }

        self.assertEqual(
            install_rootfs._deployment_mountpoints(installation_plan),
            frozenset({"home", "var", "srv", ".snapshots"}),
        )

    def test_target_rootfs_uses_standard_modes_under_private_service_umask(self) -> None:
        original = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as name:
                target = Path(name) / "target"
                with install_rootfs._target_rootfs_umask():
                    target.mkdir()
                self.assertEqual(target.stat().st_mode & 0o777, 0o755)
                current = os.umask(0o077)
                os.umask(current)
                self.assertEqual(current, 0o077)
        finally:
            os.umask(original)

    def test_account_password_is_sent_only_over_stdin_to_yescrypt_chpasswd(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            shadow = root / "etc/shadow"
            shadow.parent.mkdir(parents=True)
            shadow.write_text("kitpro-admin:$y$j9T$salt$" + "a" * 43 + ":1:2:3:4:5:6:7\n")

            def completed(*_args: object, **_kwargs: object) -> mock.Mock:
                return mock.Mock(returncode=0, stderr="")

            with mock.patch.object(
                install_rootfs.configure_account_password.__globals__["subprocess"],
                "run",
                side_effect=completed,
            ) as run:
                install_rootfs.configure_account_password(
                    root,
                    "kitpro-admin",
                    plaintext="a",
                )
            command = run.call_args.args[0]
            self.assertIn("--crypt-method", command)
            self.assertIn("YESCRYPT", command)
            self.assertNotIn("a", command)
            self.assertEqual(run.call_args.kwargs["input"], "kitpro-admin:a\n")

    def test_wait_online_accepts_any_routable_wired_interface(self) -> None:
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            install_rootfs.kitpro_phase2, "run"
        ):
            root = Path(name)
            install_rootfs._configure_services(root, parse_spec(valid_document()))
            drop_in = (
                root
                / "etc/systemd/system/systemd-networkd-wait-online.service.d"
                / "10-kitpro-any-interface.conf"
            ).read_text()
        self.assertIn("ExecStart=\n", drop_in)
        self.assertIn(
            "systemd-networkd-wait-online --any --ipv4 --timeout=30", drop_in
        )

    def test_first_boot_network_checks_are_interface_agnostic(self) -> None:
        for static in (False, True):
            with self.subTest(static=static), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                value = copy.deepcopy(valid_document())
                if static:
                    value["network"] = {
                        "mode": "static",
                        "address": "10.0.2.15",
                        "prefix": 24,
                        "gateway": "10.0.2.2",
                        "dns": ["10.0.2.3"],
                    }
                install_rootfs._configure_first_boot_validation(
                    root, parse_spec(value), 199
                )
                script = (
                    root / "usr/lib/kitpro-linux/install-first-boot-validate"
                ).read_text()
                self.assertIn("! runuser -u kitpro-admin -- sudo -n id -u", script)
                self.assertIn("%wheel ALL=(ALL:ALL) ALL", script)
                self.assertNotIn('test "$(runuser -u kitpro-admin -- sudo -n id -u)" = 0', script)
                self.assertNotIn("enp0s3", script)
                self.assertIn(
                    "networkctl --no-pager --no-legend | grep -q 'routable'",
                    script,
                )
                if static:
                    self.assertIn("10.0.2.15/24", script)
                    self.assertIn("resolvectl dns | grep -Fq '10.0.2.3'", script)
                else:
                    self.assertIn(
                        "ip -4 -o address show scope global dynamic | grep -q .",
                        script,
                    )

    def test_local_and_serial_gettys_are_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as name, mock.patch.object(
            install_rootfs.kitpro_phase2, "run"
        ) as run:
            enabled = install_rootfs._configure_services(
                Path(name), parse_spec(valid_document())
            )
        self.assertIn("getty@tty1.service", enabled)
        self.assertIn("serial-getty@ttyS0.service", enabled)
        enable = run.call_args_list[0].args[0]
        self.assertIn("getty@tty1.service", enable)
        self.assertIn("serial-getty@ttyS0.service", enable)

    def test_first_boot_package_count_comes_from_the_install_plan(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "tools/install/rootfs.py").read_text()
        self.assertIn('plan["repository"]["package_count"]', source)
        self.assertIn('wc -l)" -eq {package_count}', source)
        self.assertNotIn('wc -l)" -eq 167', source)

    def test_mkinitcpio_uses_target_tmp_inside_chroot(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "tools/install/rootfs.py").read_text()
        self.assertIn('"TMPDIR=/tmp"', source)

    def fixture(self, root: Path, static: bool = False, ssh_enabled: bool = True) -> object:
        value = copy.deepcopy(valid_document())
        if static:
            value["network"] = {
                "mode": "static", "address": "10.0.2.15", "prefix": 24,
                "gateway": "10.0.2.2", "dns": ["10.0.2.3"],
            }
        if not ssh_enabled:
            value["ssh"] = {"enabled": False}
            value["firewall"] = {"ssh": False}
            value["administrator"]["ssh_authorized_keys"] = []
        spec = parse_spec(value)
        files = {
            "etc/fstab": fstab_from_plan(plan()),
            "etc/hostname": spec.system.hostname + "\n",
            "etc/systemd/network/20-kitpro.network": networkd(spec),
            "etc/systemd/system/systemd-networkd-wait-online.service.d/10-kitpro-any-interface.conf": (
                "[Service]\nExecStart=\n"
                "ExecStart=/usr/lib/systemd/systemd-networkd-wait-online "
                "--any --ipv4 --timeout=30\n"
            ),
            "etc/nftables.conf": nftables(spec),
            "etc/ssh/sshd_config.d/10-kitpro-server.conf": (
                "PermitRootLogin no\nPasswordAuthentication no\n"
                "KbdInteractiveAuthentication no\nPubkeyAuthentication yes\n"
                "AuthenticationMethods publickey\n"
            ),
            "etc/sudoers.d/10-kitpro-installer-admin": "%wheel ALL=(ALL:ALL) ALL\n",
            "efi/loader/entries/kitpro-linux.conf": loader_entry("root-id"),
            "efi/loader/entries/kitpro-linux-compatibility.conf": loader_entry(
                "root-id", compatibility_graphics=True
            ),
            "etc/pacman.conf": (
                "[options]\nSigLevel = Required DatabaseRequired TrustedOnly\n"
                "LocalFileSigLevel = Required TrustedOnly\n[kitpro-0.1-dev-core]\n"
                "Server = https://repo.invalid/stable/0.1-dev/0.1-dev-g0002/core/os/$arch\n"
            ),
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (root / "usr/share/zoneinfo").mkdir(parents=True)
        (root / "usr/share/zoneinfo/UTC").write_text("zone")
        (root / "etc/localtime").symlink_to("../usr/share/zoneinfo/UTC")
        status = root / "usr/bin/kitpro-kernel-status"
        status.parent.mkdir(parents=True)
        status.write_text("#!/usr/bin/bash\n")
        status.chmod(0o755)
        health = root / "usr/bin/kitpro-health"
        health.write_text("#!/usr/bin/bash\n")
        health.chmod(0o755)
        support = root / "usr/bin/kitpro-support-bundle"
        support.write_text("#!/usr/bin/bash\n")
        support.chmod(0o755)
        inspector = root / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py"
        inspector.parent.mkdir(parents=True)
        inspector.write_text("# installed inspection fixture\n")
        return spec

    def test_dhcp_and_static_profiles_validate(self) -> None:
        for static in (False, True):
            with self.subTest(static=static), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                spec = self.fixture(root, static=static)
                validate_configured_rootfs(root, spec, plan())

    def test_ssh_disabled_profile_has_no_firewall_exception(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            spec = self.fixture(root, ssh_enabled=False)
            validate_configured_rootfs(root, spec, plan())
            self.assertNotIn("tcp dport 22", (root / "etc/nftables.conf").read_text())

    def test_mutable_repository_pointer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            spec = self.fixture(root)
            config = root / "etc/pacman.conf"
            config.write_text(config.read_text().replace("0.1-dev-g0002", "current"))
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "not pinned"):
                validate_configured_rootfs(root, spec, plan())

    def test_development_repository_configuration_is_immutable_and_strict(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            spec = self.fixture(root)
            install_rootfs._configure_immutable_development_repository(root, spec)
            config = (root / "etc/pacman.conf").read_text()
            self.assertIn("stable/0.1-dev/0.1-dev-g0002/core/os/$arch", config)
            self.assertNotIn("/current/", config)
            self.assertIn("SigLevel = Required DatabaseRequired TrustedOnly", config)
            validate_configured_rootfs(root, spec, plan())

    def test_invalid_firewall_ssh_and_boot_configuration_fail(self) -> None:
        mutations = (
            ("etc/nftables.conf", "invalid", "nftables"),
            ("etc/ssh/sshd_config.d/10-kitpro-server.conf", "PermitRootLogin yes\n", "SSH"),
            ("etc/sudoers.d/10-kitpro-installer-admin", "%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n", "sudo"),
            (
                "etc/systemd/system/systemd-networkd-wait-online.service.d/10-kitpro-any-interface.conf",
                "invalid\n",
                "network readiness",
            ),
            ("efi/loader/entries/kitpro-linux.conf", "invalid", "wrong root"),
        )
        for relative, content, message in mutations:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                spec = self.fixture(root)
                (root / relative).write_text(content)
                with self.assertRaisesRegex(kitpro_repo.PipelineError, message):
                    validate_configured_rootfs(root, spec, plan())

    def test_base_rootfs_copy_preserves_execute_only_mode(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            temporary = Path(name)
            source = temporary / "source"
            destination = temporary / "destination"
            helper = source / "usr/lib/helper"
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b"executable")
            helper.chmod(0o4110)
            with mock.patch.object(install_rootfs, "BASE_ROOTFS", source):
                install_rootfs._copy_base_rootfs(destination)
            self.assertEqual(helper.stat().st_mode & 0o7777, 0o4110)
            self.assertEqual((destination / "usr/lib/helper").stat().st_mode & 0o7777, 0o4110)

    def test_kernel_boot_validation_is_independent_of_first_boot(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            install_rootfs._configure_kernel_boot_validation(root)
            script = (root / "usr/lib/kitpro-linux/kernel-boot-validate").read_text()
            unit = (
                root / "usr/lib/systemd/system/kitpro-kernel-boot-validation.service"
            ).read_text()
            self.assertIn("record-successful-boot", script)
            self.assertIn("KITPRO_KERNEL_BOOT_OK", script)
            self.assertIn("source_repository_generation", script)
            self.assertIn("identity_generation", script)
            self.assertIn('(current|$identity_generation)', script)
            self.assertIn('[kitpro-$product_release-core]', script)
            self.assertNotIn('test "$identity_generation" = "$kernel_generation"', script)
            self.assertEqual(script, install_rootfs.KERNEL_BOOT_VALIDATE.read_text())
            self.assertIn("grep -v 'kitpro-kernel-boot-validation.service'", script)
            self.assertIn("After=kitpro-install-first-boot-validation.service", unit)
            self.assertNotIn("ConditionPathExists", unit)

    def test_kernel_lifecycle_keeps_local_and_serial_console_without_debug_shell(self) -> None:
        source = install_rootfs.KERNEL_RUNTIME.read_text()
        self.assertIn("console=ttyS0,115200n8 console=tty0", source)
        self.assertIn("lsm=landlock,lockdown,yama,integrity,apparmor,bpf", source)
        self.assertIn("apparmor=1 security=apparmor", source)
        self.assertNotIn("systemd.debug_shell", source)


if __name__ == "__main__":
    unittest.main()
