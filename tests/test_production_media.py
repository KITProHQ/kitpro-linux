from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo, production_media

ROOT = Path(__file__).resolve().parents[1]


class ProductionQualificationMediaTests(unittest.TestCase):
    def test_runtime_module_closure_contains_generation_validation_dependencies(self):
        self.assertIn('generation_descriptor.py', production_media.RUNTIME_MODULES)
        self.assertIn('release_repository.py', production_media.RUNTIME_MODULES)

    def test_dirty_source_cannot_stage_qualification_media(self):
        with mock.patch.object(production_media.phase5, '_git_state', return_value=('a' * 40, True)):
            with self.assertRaisesRegex(kitpro_repo.PipelineError, 'clean source'):
                production_media.stage_qualification_profile(ROOT, Path('/unused'), Path('/unused'))

    def test_qualification_identity_is_separate_from_rc1_and_active_policy_is_production(self):
        explicit = json.loads(
            (ROOT / 'config/production-install-rootfs-profile.json').read_text()
        )['explicit_packages']
        packages = [{'name': name, 'explicit': True} for name in explicit]
        keyring = next(item for item in packages if item['name'] == 'kitpro-linux-keyring')
        keyring.update(filename='keyring.pkg.tar.zst', sha256=production_media.KEYRING_SHA256)
        manifest = {
            'generation_id': '1.0-g0002', 'source': {'epoch': 1790000000},
            'packages': packages,
            'package_count': 199, 'explicit_package_count': 36, 'artifact_set_sha256': 'b' * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generation = root / 'generation'
            generation.mkdir()
            (generation / 'manifest.json').write_text(json.dumps(manifest))
            run = root / 'run'
            run.mkdir()
            with mock.patch.object(production_media.phase5, '_git_state', return_value=('a' * 40, False)), \
                 mock.patch.object(production_media, 'validate_generation', return_value=manifest), \
                 mock.patch.object(production_media.phase5, '_tracked_source_tree_sha256', return_value='c' * 64), \
                 mock.patch.object(kitpro_repo, 'run', return_value=mock.Mock(stdout=b'public fixture')):
                build_keyring = root / 'short-build-keyring'
                profile, config = production_media.stage_qualification_profile(
                    ROOT, generation, run, build_arch_keyring=build_keyring
                )
            self.assertEqual(config['iso_filename'], 'kitpro-linux-server-1.0-memory-qualification-x86_64.iso')
            self.assertTrue(config['qualification_only'])
            live = profile / 'airootfs'
            project = live / 'opt/kitpro-linux'
            metadata = json.loads((project / 'media/source-metadata.json').read_text())
            self.assertEqual(metadata['product_version'], '1.0')
            self.assertEqual(metadata['repository_generation'], '1.0-g0002')
            self.assertNotIn('rc1', metadata['media_build_identity'])
            self.assertEqual((live / 'etc/pacman.conf').read_text(), production_media.production_pacman_config())
            self.assertFalse((project / '.state/dev-keys').exists())
            self.assertNotIn('repo.home', (project / 'config/install-rootfs-profile.json').read_text())
            self.assertIn('iso_version="1.0-memory-qualification"', (profile / 'profiledef.sh').read_text())
            build_pacman = (profile / 'pacman.conf').read_text()
            self.assertIn(f'GPGDir = {build_keyring}', build_pacman)
            self.assertIn('SigLevel = Required DatabaseOptional TrustedOnly', build_pacman)
            self.assertIn('LocalFileSigLevel = Required TrustedOnly', build_pacman)

class UpstreamLiteralClassificationTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory) / 'root'
        binary = root / 'usr/bin/ssh'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'ELF fixture with private-key parser literal')
        database = root / 'var/lib/pacman/local/openssh-1-1/desc'
        database.parent.mkdir(parents=True)
        database.write_text('%NAME%\nopenssh\n\n%VERSION%\n1-1\n\n')
        cache = Path(directory) / 'cache'
        cache.mkdir()
        package = cache / 'openssh-1-1-x86_64.pkg.tar.zst'
        package.write_bytes(b'signed package fixture')
        return root, binary, cache

    def test_only_exact_signed_upstream_bytes_are_classified(self):
        with tempfile.TemporaryDirectory() as directory:
            root, binary, cache = self.fixture(directory)
            finding = {'path': 'usr/bin/ssh', 'kind': 'private-key-armor'}
            with mock.patch.object(kitpro_repo, 'verify_signature', return_value='A' * 40) as verify, \
                 mock.patch.object(kitpro_repo, 'run', return_value=mock.Mock(stdout=binary.read_bytes())):
                remaining, classified = production_media.classify_upstream_literals(root, cache, root, [finding])
            self.assertEqual(remaining, [])
            self.assertEqual(len(classified), 1)
            verify.assert_called_once()

    def test_appended_key_material_cannot_hide_in_an_upstream_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root, binary, cache = self.fixture(directory)
            original = binary.read_bytes()
            binary.write_bytes(original + b'\n-----BEGIN PRIVATE KEY-----\nadded material')
            with mock.patch.object(kitpro_repo, 'verify_signature', return_value='A' * 40), \
                 mock.patch.object(kitpro_repo, 'run', return_value=mock.Mock(stdout=original)):
                with self.assertRaisesRegex(kitpro_repo.PipelineError, 'differs from signed package'):
                    production_media.classify_upstream_literals(root, cache, root,
                        [{'path': 'usr/bin/ssh', 'kind': 'private-key-armor'}])

    def test_private_key_paths_and_tokens_are_never_classified(self):
        findings = [{'path': 'usr/bin/ssh', 'kind': 'github-token'},
                    {'path': 'root/.ssh/id_ed25519', 'kind': 'private-key-path'}]
        remaining, classified = production_media.classify_upstream_literals(Path('/unused'), Path('/unused'), Path('/unused'), findings)
        self.assertEqual(remaining, findings)
        self.assertEqual(classified, [])
