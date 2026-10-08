import unittest
from tools.support_bundle import canonical_member_order, ValidationError

class CanonicalSupportOrderTests(unittest.TestCase):
    def test_bytewise_path_order(self):
        self.assertEqual(canonical_member_order(['boot/loader.conf', 'boot/loader-entries/2.conf', 'boot/loader-entries/10.conf']),
                         ['boot/loader-entries/10.conf', 'boot/loader-entries/2.conf', 'boot/loader.conf'])
    def test_unsafe_and_duplicate_names_rejected(self):
        for paths in [['../unsafe'], ['same', 'same'], ['a//b']]:
            with self.assertRaises(ValidationError): canonical_member_order(paths)
