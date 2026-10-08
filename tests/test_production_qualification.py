from pathlib import Path
import tempfile
import unittest
from tools.production_qualification import write_build_report


class QualificationBuildEvidenceTests(unittest.TestCase):
    def test_report_can_finish_after_resumed_disk_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            for name in ('baseline.raw', 'tcg.raw', 'kvm.raw'):
                with (work / name).open('wb') as stream:
                    stream.truncate(16 * 1024**3)
            for name in ('repository-identity', 'kernel-boot-validate', 'kernel-lifecycle', 'system-health', 'python/tools/support_bundle_inspect.py'):
                p = work / 'rootfs/usr/lib/kitpro-linux' / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('test runtime')
            manifest = {'packages': [{'explicit': i < 36} for i in range(199)]}
            report = write_build_report(work, manifest)
            self.assertEqual(report['explicit_count'], 36)
            self.assertEqual(report['status'], 'built-awaiting-boot')
            self.assertTrue((work / 'baseline-build.json').is_file())
            self.assertEqual(len(report['runtime_sha256']), 5)

    def test_incomplete_disk_never_emits_success_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'baseline.raw').write_bytes(b'incomplete')
            with self.assertRaisesRegex(ValueError, 'disk size'):
                write_build_report(work, {'packages': []})
            self.assertFalse((work / 'baseline-build.json').exists())
