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
    def test_cleanup_stops_only_the_mounted_client_keyring(self):
        p = plan()
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
        ) as command:
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
                with self.assertRaisesRegex(kitpro_repo.PipelineError,'partition validation'):
                    with engine.mounted_install_target(Path('/dev/qualification-only'),plan(),Path(directory)):
                        self.fail('unsafe target mounted')
                self.assertFalse(any(c.args[0][0]=='mount' for c in command.call_args_list))

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
