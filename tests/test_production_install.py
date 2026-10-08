from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install import production


class ProductionInstallTests(unittest.TestCase):
    def test_armored_and_binary_keyrings_are_imported_as_separate_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rings = root / 'public'
            rings.mkdir()
            for name in ('archlinux.gpg', 'kitpro-linux.gpg', 'archlinux-trusted',
                         'kitpro-linux-trusted', 'archlinux-revoked', 'kitpro-linux-revoked'):
                (rings / name).write_bytes(name.encode())
            manifest = {'packages': [{'name': 'kitpro-linux-keyring',
                         'sha256': production.KEYRING_SHA256, 'filename': 'keyring.pkg.tar.zst'}]}
            with mock.patch.object(production, 'source', return_value=(root, manifest)), \
                 mock.patch.object(production, 'TRUST', root / 'verification'), \
                 mock.patch.object(production, 'PUBLIC_KEYRINGS', rings), \
                 mock.patch.object(kitpro_repo, 'run', side_effect=lambda command, **kw:
                                   mock.Mock(stdout=Path(command[-1]).name.encode())), \
                 mock.patch.object(kitpro_repo, 'initialize_public_keyring') as initialize:
                production.prepare_trust('1.0-g0002', root)
            self.assertEqual(initialize.call_args.args[1], rings / 'kitpro-linux.gpg')
            self.assertEqual(initialize.call_args.kwargs['additional_public_keyrings'],
                             (rings / 'archlinux.gpg',))

    def test_unqualified_generation_is_rejected_before_reading(self):
        with mock.patch.object(production, 'validate_bytes') as validate:
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'not qualified'):
                production.source('1.0-g0003', Path('/unused'))
            validate.assert_not_called()

    def test_changed_generation_fails_before_trust_bootstrap(self):
        with mock.patch.object(production, 'validate_bytes', side_effect=ValueError('hash mismatch')), \
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
        profile = {'generation': '1.0-g0002', 'explicit_packages': ['example']}
        manifest = {'packages': [{'name': 'example', 'explicit': True}]}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(production, 'source', return_value=(Path('/repo'), manifest)), \
             mock.patch.object(kitpro_repo, 'run') as run:
            root = Path(directory)
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'empty mounted target'):
                production.deploy(profile, Path('/repo'), root, root / 'scratch', root / 'artifacts')
            run.assert_not_called()
