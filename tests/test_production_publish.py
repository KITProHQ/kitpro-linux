from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools import production_publish as publish


def fixture(root, generation, previous=None):
    directory = root / generation
    repo = directory / "core/os/x86_64"
    repo.mkdir(parents=True)
    packages = []
    for index in range(199):
        filename = f"fixture-{index}.pkg.tar.zst"
        (repo / filename).write_bytes(f"fixture {index}".encode())
        (repo / (filename + ".sig")).write_bytes(f"fixture signature {index}".encode())
        packages.append({"name": f"fixture-{index}", "filename": filename, "signature_filename": filename + ".sig", "sha256": publish.digest(repo / filename), "signature_sha256": publish.digest(repo / (filename + ".sig"))})
    for name in ("kitpro-1.0-core.db", "kitpro-1.0-core.db.tar.gz"):
        (repo / name).write_bytes(b"fixture database")
        (repo / (name + ".sig")).write_bytes(b"fixture database signature")
    inventory = [{"path": p.relative_to(directory).as_posix(), "sha256": publish.digest(p)} for p in sorted(repo.iterdir())]
    m = {"release": "1.0", "generation_id": generation, "predecessor": previous,
         "qualification_state": "signed-awaiting-client-qualification", "package_count": 199, "explicit_package_count": 36,
         "packages": packages, "database": {"sha256": publish.digest(repo / "kitpro-1.0-core.db"), "signature_sha256": publish.digest(repo / "kitpro-1.0-core.db.sig")},
         "artifact_set_sha256": hashlib.sha256((json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()).hexdigest()}
    (directory / "manifest.json").write_text(json.dumps(m))
    return directory, publish.digest(directory / "manifest.json"), m


class ProductionPublicationTests(unittest.TestCase):
    def test_publication_does_not_advance_current_and_cannot_replace_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, digest, m = fixture(root / "source", "1.0-g0001")
            public = root / "public"
            publish.publish(source, public, digest)
            self.assertFalse((public / "stable/1.0/current").exists())
            self.assertEqual(publish.validate(public / "stable/1.0/1.0-g0001", digest), m)
            with self.assertRaisesRegex(ValueError, "already exists"):
                publish.publish(source, public, digest)

    def test_pointer_requires_public_verification_and_never_moves_backward(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = root / "public"
            for g, previous in (("1.0-g0001", None), ("1.0-g0002", "1.0-g0001")):
                source, digest, m = fixture(root / "source", g, previous)
                publish.publish(source, public, digest)
                verification = root / f"{g}-verified.json"
                verification.write_text(json.dumps({"status": "passed", "generation": g, "manifest_sha256": digest, "artifact_set_sha256": m["artifact_set_sha256"]}))
                publish.advance(public, g, previous or "none", digest, verification)
            self.assertEqual((public / "stable/1.0/current").readlink().name, "1.0-g0002")
            g1 = public / "stable/1.0/1.0-g0001"
            with self.assertRaises(ValueError):
                publish.advance(public, "1.0-g0001", "none", publish.digest(g1 / "manifest.json"), root / "1.0-g0001-verified.json")

    def test_corruption_or_extra_file_prevents_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, digest, _ = fixture(root / "source", "1.0-g0001")
            (source / "operator-notes.txt").write_text("not public")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                publish.publish(source, root / "public", digest)


if __name__ == "__main__":
    unittest.main()
