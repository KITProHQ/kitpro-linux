import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import production_media, kitpro_repo
from tools.guided_installer import MediaIdentity
from tools.install.receipt import load_source_metadata

ROOT = Path(__file__).resolve().parents[1]


class RC3PresentationTests(unittest.TestCase):
    def test_metadata_renders_rc3_and_keeps_product_version(self):
        policy = json.loads((ROOT / 'config/releases/1.0-rc3.json').read_text())
        identity = production_media.release_identity(ROOT, ROOT / 'config/releases/1.0-rc3.json')
        self.assertEqual(identity['filename'], 'kitpro-linux-server-1.0-rc3-x86_64.iso')
        value = {key: policy[key] for key in ('product_name', 'product_version', 'release_status',
                    'repository_release', 'repository_generation', 'media_build_identity')}
        value.update(kind='production-iso', media_version='1.0-rc3', source_git_commit='a'*40,
                     profile_sha256='b'*64, build_configuration_sha256='c'*64)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'metadata.json'; path.write_text(json.dumps(value))
            self.assertEqual(MediaIdentity.from_source_metadata(load_source_metadata(path)).title(),
                             'KITPro Linux Server 1.0 RC3')

