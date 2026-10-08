import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools import production_media, kitpro_repo
from tools.guided_installer import MediaIdentity
from tools.install.receipt import load_source_metadata

ROOT = Path(__file__).resolve().parents[1]


class RC2PresentationTests(unittest.TestCase):
    def test_metadata_renders_rc2_and_keeps_product_version(self):
        policy = json.loads((ROOT / 'config/releases/1.0-rc2.json').read_text())
        identity = production_media.release_identity(ROOT, ROOT / 'config/releases/1.0-rc2.json')
        self.assertEqual(identity['filename'], 'kitpro-linux-server-1.0-rc2-x86_64.iso')
        value = {key: policy[key] for key in ('product_name', 'product_version', 'release_status',
                    'repository_release', 'repository_generation', 'media_build_identity')}
        value.update(kind='production-iso', media_version='1.0-rc2', source_git_commit='a'*40,
                     profile_sha256='b'*64, build_configuration_sha256='c'*64)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'metadata.json'; path.write_text(json.dumps(value))
            self.assertEqual(MediaIdentity.from_source_metadata(load_source_metadata(path)).title(),
                             'KITPro Linux Server 1.0 RC2')

    def test_python_rescue_error_and_help_literals_are_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            live = Path(temporary); path = live / 'opt/kitpro-linux/tools/rescue.py'
            path.parent.mkdir(parents=True)
            for text in ('development shell', 'Phase 3 supports only UEFI', 'Developer CLI',
                         'PRE-RELEASE INSTALLATION MEDIA', '0.1-dev', 'alpha', 'g0010'):
                path.write_text('print(' + repr(text) + ')\n')
                with self.assertRaises(kitpro_repo.PipelineError):
                    production_media.validate_presentation(live, live / 'entries')
            path.write_text('from tools import phase4_live\nprint("KITPro Linux Rescue maintenance shell")\n')
            production_media.validate_presentation(live, live / 'entries')

    def test_rendered_command_help_has_no_engineering_branding(self):
        for module in ('tools.install', 'tools.rescue', 'tools.guided_installer', 'tools.phase4_live'):
            result = subprocess.run(['python', '-m', module, '--help'], text=True, capture_output=True, check=True)
            # argparse usage includes the implementation module filename; its
            # descriptive text must be product-facing.
            content = '\n'.join(result.stdout.splitlines()[2:])
            self.assertIsNone(production_media.PRESENTATION_PATTERN.search(content), module)
