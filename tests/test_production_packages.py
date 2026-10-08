from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import production_packages as packages
from tools.production_repository import contamination_findings


def armor(data: bytes) -> bytes:
    return (b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + base64.b64encode(data)
            + b"\n-----END PGP PUBLIC KEY BLOCK-----\n")


class ProductionPackageTests(unittest.TestCase):
    def test_secret_packets_in_public_armor_are_rejected_before_import(self):
        for tag in (5, 7):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "secret"):
                packages.public_packets(armor(bytes([0xc0 | tag, 1, 0])))

    def test_multiple_primary_keys_rejected(self):
        with self.assertRaisesRegex(ValueError, "one primary"):
            packages.public_packets(armor(bytes([0xc6, 1, 0, 0xc6, 1, 0])))

    def test_partial_lengths_rejected(self):
        with self.assertRaisesRegex(ValueError, "partial"):
            packages.public_packets(armor(bytes([0xc6, 224])))

    def test_truncated_packet_rejected(self):
        for data in (b"\xc6", b"\xc6\xc0", b"\xc6\xff\x00", b"\x99\x00", b"\xc6\x05\x00"):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, "truncated"):
                packages.public_packets(armor(data))

    def test_wrong_export_hash_fails_before_tar_processing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "export.tar.gz"
            path.write_bytes(b"unapproved archive")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                packages.read_public_export(path)

    def test_sources_preserve_dependencies_and_separate_trust_roles(self):
        keys = {role: armor(bytes([0xc6, 1, index]))
                for index, role in enumerate(packages.FINGERPRINTS)}
        ceremony = {"keys": [{"role": role, "fingerprint": fingerprint}
                             for role, fingerprint in packages.FINGERPRINTS.items()]}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(packages, "read_public_export", return_value=(keys, ceremony)), \
                patch.object(packages, "verify_public_keys", return_value={"tested": True}):
            output = Path(temporary) / "sources"
            result = packages.prepare(Path("unused"), output)
            self.assertEqual(len(result["packages"]), 4)
            self.assertEqual(contamination_findings(output), [])
            ring = (output / "kitpro-linux-keyring/kitpro-linux.gpg").read_bytes()
            self.assertEqual(ring, b"".join(packages.public_packets(keys[role])
                                          for role in packages.PACMAN_ROLES))
            trusted = (output / "kitpro-linux-keyring/kitpro-linux-trusted").read_text()
            self.assertEqual(trusted, packages.FINGERPRINTS["root"] + ":5:\n")
            base = (output / "kitpro-linux-base/PKGBUILD").read_text()
            original = (packages.ROOT / "packages/kitpro-linux-base/PKGBUILD").read_text()
            self.assertEqual(base.split("depends=(", 1)[1], original.split("depends=(", 1)[1])
            config = (output / "kitpro-linux-release/pacman.conf").read_text()
            self.assertIn("SigLevel = Required DatabaseRequired TrustedOnly", config)
            self.assertIn("https://repo.kitpro.us/kitpro-linux/stable/1.0/current/", config)
            with self.assertRaisesRegex(ValueError, "already exists"):
                packages.prepare(Path("unused"), output)


if __name__ == "__main__":
    unittest.main()
