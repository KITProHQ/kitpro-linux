from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from tools import kitpro_repo
from tools.install import engine
from tests.test_install_engine import plan

class DirectDeploymentTests(unittest.TestCase):
    def test_reused_esp_result_requires_dedicated_boot_manager(self):
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "lacks the KITPro boot manager"):
            engine._validate_reused_esp_result(
                {"vendor/existing.efi": "a" * 64},
                {"vendor/existing.efi": "a" * 64},
            )

    def test_reused_esp_result_preserves_existing_files(self):
        loader = {"EFI/KITPRO/kitpro-bootx64.efi": "b" * 64}
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "changed pre-existing files"):
            engine._validate_reused_esp_result(
                {"vendor/existing.efi": "a" * 64},
                {"vendor/existing.efi": "c" * 64, **loader},
            )
        engine._validate_reused_esp_result(
            {"vendor/existing.efi": "a" * 64},
            {"vendor/existing.efi": "a" * 64, **loader},
        )

    def test_reused_esp_audit_uses_privileged_service_writable_runtime(self):
        p = plan()
        p["plan_sha256"] = "a" * 64
        p["partition_table"]["esp"]["action"] = "reuse"
        commands = []

        def recorded(args, *unused):
            commands.append(args)
            return mock.Mock(stdout="")

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            engine, "INSTALL_MOUNT_ROOT", Path(directory) / "kitpro-installations"
        ), mock.patch.object(
            engine, "_planned_partition_devices", return_value={"esp": "/dev/test1"}
        ), mock.patch.object(engine, "_recorded_command", side_effect=recorded):
            self.assertEqual(
                engine._snapshot_reused_esp(Path("/dev/test"), p, Path(directory), "before"),
                {},
            )

        mount = next(args for args in commands if args[0] == "mount")
        self.assertIn("/kitpro-installations/esp-audit-", mount[-1])

    def test_preserved_unmounted_partition_is_never_added_to_deployment_mounts(self):
        p = plan()
        p["plan_sha256"] = "a" * 64
        table = p["partition_table"]
        table["layout"] = "preserve"
        table["esp"]["filesystem"] = "vfat"
        table["root"]["filesystem"] = "ext4"
        table["partitions"] = [
            {"role": "preserved-1", "action": "preserve", "mount_point": None},
            {"role": "esp", "action": "create", "mount_point": "/efi"},
            {"role": "root", "action": "create", "mount_point": "/"},
        ]
        devices = {"esp": "/dev/test2", "root": "/dev/test3"}
        commands = []

        def recorded(args, *unused):
            commands.append(args)
            return mock.Mock(stdout=json.dumps({"blockdevices": []}))

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            engine, "_planned_partition_devices", return_value=devices
        ), mock.patch.object(
            engine, "_recorded_command", side_effect=recorded
        ), mock.patch.object(
            engine, "INSTALL_MOUNT_ROOT", Path(directory) / "mounts"
        ):
            with engine.mounted_install_target(
                Path("/dev/test"), p, Path(directory)
            ):
                pass

        mounted_devices = [args[1] for args in commands if args[0] == "mount"]
        self.assertEqual(mounted_devices, [devices["root"], devices["esp"]])
        self.assertFalse(any("preserved-1" in arg for args in commands for arg in args))

    def test_cleanup_stops_only_the_mounted_client_keyring(self):
        p = plan()
        p["plan_sha256"] = "a" * 64
        for role, filesystem in (("esp", "vfat"), ("root", "ext4")):
            p["partition_table"][role]["filesystem"] = filesystem
        children = [
            dict(path=f"/dev/qualification-only{i}", type="part", mountpoints=[None],
                 partuuid=p["partition_table"][role]["partition_uuid"],
                 fstype=p["partition_table"][role]["filesystem"])
            for i, role in enumerate(("esp", "root"), 1)
        ]
        response = mock.Mock(stdout=json.dumps({"blockdevices": [
            {"path": "/dev/qualification-only", "children": children}
        ]}))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            engine, "_recorded_command", return_value=response
        ) as command, mock.patch.object(
            engine, "INSTALL_MOUNT_ROOT", Path(directory) / "mounts"
        ):
            with engine.mounted_install_target(
                Path("/dev/qualification-only"), p, Path(directory)
            ) as root:
                keyring = root / "etc/pacman.d/gnupg"
                keyring.mkdir(parents=True)
                public = keyring / "pubring.gpg"
                public.write_bytes(b"public fixture")
            self.assertEqual(public.read_bytes(), b"public fixture")
            calls = [call.args[0] for call in command.call_args_list]
            self.assertEqual([c for c in calls if c[0] == "gpgconf"], [
                ["gpgconf", "--homedir", str(keyring), "--kill", "all"]
            ])

    def test_unmount_failure_still_attempts_parent_cleanup(self):
        p = plan()
        p["plan_sha256"] = "a" * 64
        p["partition_table"]["esp"]["filesystem"] = "vfat"
        p["partition_table"]["root"]["filesystem"] = "ext4"
        children = [
            dict(path=f"/dev/qualification-only{i}", type="part", mountpoints=[None],
                 partuuid=p["partition_table"][role]["partition_uuid"],
                 fstype=p["partition_table"][role]["filesystem"])
            for i, role in enumerate(("esp", "root"), 1)
        ]
        commands = []

        def command(args, *unused):
            commands.append(args)
            if args[0] == "umount" and args[1].endswith("/efi"):
                raise kitpro_repo.PipelineError("simulated busy ESP")
            return mock.Mock(stdout=json.dumps({"blockdevices": [
                {"path": "/dev/qualification-only", "children": children}
            ]}))

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            engine, "_recorded_command", side_effect=command
        ), mock.patch.object(
            engine, "INSTALL_MOUNT_ROOT", Path(directory) / "mounts"
        ):
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "target unmount failed"):
                with engine.mounted_install_target(
                    Path("/dev/qualification-only"), p, Path(directory)
                ):
                    pass
        self.assertEqual([c[0] for c in commands[-2:]], ["umount", "umount"])

    def test_empty_partition_definitions_never_request_tree_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            result=engine.render_repart_definitions(Path(directory),plan(),populate=False)
            text=''.join(p.read_text() for p in result.glob('*.conf'))
            self.assertIn('Format=ext4',text); self.assertIn('Format=vfat',text)
            self.assertNotIn('CopyFiles=',text); self.assertNotIn('ExcludeFiles=',text)

    def test_modified_state_survives_later_configuration_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            p=plan();p['plan_sha256']='a'*64;p['target']={'path':'/dev/qualification-only'}
            with mock.patch.object(engine,'INSTALLATION_ROOT',Path(directory)):
                engine.write_state(p,'partitioning')
                engine.write_state(p,'configuration')
                engine.write_state(p,'failed','failed','configuration failed')
                result=json.loads(engine._state_path(p).read_text())
                self.assertTrue(result['disk_may_be_modified'])
                self.assertEqual(result['result'],'failed')

    def test_wrong_partition_uuid_is_rejected_before_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            response=mock.Mock(stdout=json.dumps({'blockdevices':[{'path':'/dev/qualification-only','children':[{'path':'/dev/qualification-only1','partuuid':'wrong','type':'part','fstype':'vfat','mountpoints':[None]}]}]}))
            with mock.patch.object(engine,'_recorded_command',return_value=response) as command:
                with mock.patch.object(engine,'INSTALL_MOUNT_ROOT',Path(directory)/'mounts'):
                    with self.assertRaisesRegex(kitpro_repo.PipelineError,'partition validation'):
                        with engine.mounted_install_target(Path('/dev/qualification-only'),plan(),Path(directory)):
                            self.fail('unsafe target mounted')
                    self.assertFalse(any(c.args[0][0]=='mount' for c in command.call_args_list))

    def test_live_mountpoint_keeps_gnupg_socket_below_af_unix_limit(self):
        p = plan()
        p["plan_sha256"] = "a" * 64
        root = engine._installation_mountpoint(p)
        self.assertEqual(root, Path("/run/kitpro-installations") / ("a" * 16))
        self.assertLess(len(str(root / "etc/pacman.d/gnupg/S.gpg-agent")), 108)

    def test_source_revalidation_precedes_disk_mutation(self):
        # Exercise the owning block branch without creating or authorizing any real block device.
        p=plan();p['plan_sha256']='a'*64;p['target']={'path':'/dev/qualification-only'}
        p['install_spec_sha256']='b'*64
        spec=mock.Mock();spec.sha256.return_value=p['install_spec_sha256'];spec.disk.device='/dev/qualification-only'
        disk=mock.Mock(path='/dev/qualification-only',target_type='block')
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(engine,'validate_plan'), \
             mock.patch.object(engine,'require_erase_authorization'), \
             mock.patch.object(engine,'discover_disk',return_value=disk), \
             mock.patch.object(engine,'assert_disk_unchanged'), \
             mock.patch.object(engine,'build_receipt',return_value={}), \
             mock.patch.object(engine,'INSTALLATION_ROOT',Path(directory)/'states'), \
             mock.patch.object(engine,'EVIDENCE_ROOT',Path(directory)/'evidence'), \
             mock.patch.object(engine,'validate_install_source',side_effect=kitpro_repo.PipelineError('bad source')), \
             mock.patch.object(engine,'_prepare_block_target') as wipe:
            with self.assertRaisesRegex(kitpro_repo.PipelineError,'bad source'):engine.apply(spec,p,True)
            wipe.assert_not_called()
            failure=json.loads((Path(directory)/'evidence'/p['plan_sha256']/'failure.json').read_text())
            self.assertFalse(failure['disk_may_be_modified'])

class SemanticsInventoryTests(unittest.TestCase):
    def test_inventory_distinguishes_metadata_and_preserves_link_topology(self):
        import os
        from tools.install.semantics import inventory
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'usr').mkdir(); file=root/'usr/a';file.write_bytes(b'payload');file.chmod(0o640)
            os.link(file,root/'usr/b');os.symlink('a',root/'usr/link')
            os.setxattr(file,'user.kitpro',b'fixture')
            result=inventory(root,['usr'])
            self.assertEqual(result['hardlink_groups'],[['usr/a','usr/b']])
            self.assertEqual(result['records']['usr/a']['mode'],0o640)
            self.assertEqual(result['records']['usr/a']['xattrs']['user.kitpro'],'Zml4dHVyZQ==')
            self.assertEqual(result['records']['usr/link']['target'],'a')
