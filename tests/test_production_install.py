from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_phase2, kitpro_repo
from tools.install import production


class ProductionInstallTests(unittest.TestCase):
    def test_phase2_routes_production_signed_generation_through_production_verifier(self):
        expected = (Path('/verified'), {'generation_id': '1.1-g0001'})
        profile = {
            'release': '1.1', 'generation': '1.1-g0001', 'trust': 'production-signed'
        }
        with mock.patch.object(production, 'verify', return_value=expected) as verify, \
             mock.patch.object(kitpro_repo, 'validate_manifest') as development_validate:
            self.assertEqual(kitpro_phase2.generation(profile, Path('/repo')), expected)
        verify.assert_called_once_with('1.1-g0001', Path('/repo'))
        development_validate.assert_not_called()

    def test_installed_production_keyring_is_used_for_target_trust(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / 'usr/share/pacman/keyrings'
            public.mkdir(parents=True)
            expected = tuple(
                public / name
                for name in (
                    'kitpro-linux.gpg', 'kitpro-linux-trusted', 'kitpro-linux-revoked'
                )
            )
            for path in expected:
                path.write_bytes(b'public trust fixture')
            self.assertEqual(
                kitpro_phase2.installation_public_trust(
                    root, {'trust': 'production-signed'}
                ),
                expected,
            )

    def test_release_aware_manifest_normalizes_package_and_artifact_identity(self):
        records = [
            {
                'name': 'example', 'version': '1-1', 'filename': 'example-1-1.pkg.tar.zst',
                'sha256': 'a' * 64, 'explicit': True,
            }
        ]
        manifest = {'repositories': [{'packages': records}]}
        self.assertEqual(production.packages(manifest), records)
        self.assertEqual(
            production.artifact_set_sha256(manifest),
            kitpro_repo.artifact_set_hash(records),
        )

    def test_linux_1_1_uses_release_aware_pacman_namespace(self):
        config = production.pacman_config('1.1-g0001')
        self.assertIn('[kitpro-1.1-core]', config)
        self.assertIn('/stable/1.1/current/core/os/$arch', config)

    def test_armored_and_binary_keyrings_are_imported_as_separate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rings = root / 'public'
            rings.mkdir()
            for name in ('archlinux.gpg', 'kitpro-linux.gpg', 'archlinux-trusted',
                         'kitpro-linux-trusted', 'archlinux-revoked', 'kitpro-linux-revoked'):
                (rings / name).write_bytes(name.encode())
            manifest = {'packages': [
                {'name': 'kitpro-linux-keyring', 'sha256': production.KEYRING_SHA256,
                 'filename': 'keyring.pkg.tar.zst'},
                {'name': 'archlinux-keyring', 'filename': 'arch-keyring.pkg.tar.zst'},
            ]}
            with mock.patch.object(production, 'source', return_value=(root, manifest)), \
                 mock.patch.object(production, 'TRUST', root / 'verification'), \
                 mock.patch.object(production, 'PUBLIC_KEYRINGS', rings), \
                 mock.patch.object(kitpro_repo, 'run', side_effect=lambda command, **kw:
                                   mock.Mock(stdout=Path(command[-1]).name.encode())), \
                 mock.patch.object(kitpro_repo, 'package_member', return_value=b'public fixture'), \
                 mock.patch.object(kitpro_repo, 'initialize_public_keyring') as initialize:
                production.prepare_trust('1.0-g0002', root)
            self.assertEqual(
                initialize.call_args.args[1], root / 'verification/kitpro-linux.gpg'
            )
            self.assertEqual(initialize.call_args.kwargs['additional_public_keyrings'],
                             (root / 'verification/archlinux.gpg',))

    def test_unqualified_generation_is_rejected_before_reading(self):
        with mock.patch.object(production, 'validate_bytes') as validate:
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'not qualified'):
                production.source('1.0-g0003', Path('/unused'))
            validate.assert_not_called()

    def test_changed_generation_fails_before_trust_bootstrap(self):
        with mock.patch.object(production, 'source', side_effect=ValueError('hash mismatch')), \
             mock.patch.object(kitpro_repo, 'initialize_public_keyring') as initialize:
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                production.prepare_trust('1.0-g0002', Path('/unused'))
            initialize.assert_not_called()

    def test_wrong_repository_signer_fails_before_package_verification(self):
        manifest = {'database': {'filename': 'kitpro-1.0-core.db.tar.gz'}}
        with mock.patch.object(production, 'source', return_value=(Path('/repo'), manifest)), \
             mock.patch.object(production, 'prepare_trust', return_value=Path('/public')), \
             mock.patch.object(kitpro_repo, 'verify_signature', return_value='0' * 40), \
             mock.patch.object(production.production_generation, 'validate_inventory') as verify:
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'authority mismatch'):
                production.verify('1.0-g0002', Path('/unused'))
            verify.assert_not_called()

    def test_unmounted_root_never_initializes_keys_or_installs_packages(self):
        profile = {
            'generation': '1.0-g0002', 'explicit_packages': ['example'],
            'repository_url': 'https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/$arch',
        }
        manifest = {'packages': [{'name': 'example', 'explicit': True}]}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(production, 'source', return_value=(Path('/repo'), manifest)), \
             mock.patch.object(kitpro_repo, 'run') as run:
            root = Path(directory)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'empty mounted target'):
                production.deploy(profile, Path('/repo'), root, root / 'scratch', root / 'artifacts')
            run.assert_not_called()

    def test_declared_home_mount_is_allowed_but_must_be_a_mount(self):
        profile = {
            'generation': '1.0-g0002', 'explicit_packages': ['example'],
            'repository_url': 'https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/$arch',
        }
        manifest = {'packages': [{'name': 'example', 'explicit': True}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'target'
            root.mkdir()
            (root / 'efi').mkdir()
            (root / 'home').mkdir()
            scratch = root / '.kitpro-install-work'
            scratch.mkdir()

            def is_mount(path: Path) -> bool:
                return path in {root, root / 'home'}

            with mock.patch.object(
                production, 'source', return_value=(Path('/repo'), manifest)
            ), mock.patch.object(
                production.Path, 'is_mount', autospec=True, side_effect=is_mount
            ), mock.patch.object(
                kitpro_repo, 'run', side_effect=kitpro_repo.PipelineError('after validation')
            ), self.assertRaisesRegex(kitpro_repo.PipelineError, 'after validation'):
                production.deploy(
                    profile, Path('/repo'), root, scratch, root / 'artifacts',
                    allowed_mountpoints=frozenset({'home'}),
                )

            with mock.patch.object(
                production, 'source', return_value=(Path('/repo'), manifest)
            ), mock.patch.object(
                production.Path, 'is_mount', autospec=True,
                side_effect=lambda path: path == root,
            ), mock.patch.object(kitpro_repo, 'run') as run:
                with self.assertRaisesRegex(kitpro_repo.PipelineError, 'empty mounted target'):
                    production.deploy(
                        profile, Path('/repo'), root, scratch, root / 'artifacts',
                        allowed_mountpoints=frozenset({'home'}),
                    )
                run.assert_not_called()
