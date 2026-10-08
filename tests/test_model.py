from __future__ import annotations

import copy
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools import check_tracked_secrets
from tools import kitpro_repo


ROOT = Path(__file__).resolve().parents[1]


def package(name: str, dependencies: list[str] | None = None) -> dict[str, object]:
    digest = "a" * 64
    fingerprint = "A" * 40
    return {
        "name": name,
        "version": "1.0-1",
        "package_release": "1",
        "architecture": "x86_64",
        "filename": f"{name}-1.0-1-x86_64.pkg.tar.zst",
        "sha256": digest,
        "object_sha256": digest,
        "origin_type": "kitpro-native",
        "upstream_origin": None,
        "upstream_signature": None,
        "kitpro_signature": {
            "filename": f"{name}-1.0-1-x86_64.pkg.tar.zst.sig",
            "sha256": digest,
            "object_sha256": digest,
            "signer_fingerprint": fingerprint,
        },
        "source": {"repository": "test", "packaging_commit": "0" * 40},
        "dependencies": dependencies or [],
        "provides": [],
        "explicit": True,
        "support_class": "test",
        "update_policy": "test",
        "metadata": {},
    }


def manifest(channel: str = "stable", generation: str = "0.1-dev-g0001") -> dict[str, object]:
    digest = "b" * 64
    return {
        "schema_version": 1,
        "release": "0.1-dev",
        "generation_id": generation,
        "created_at": "2026-09-25T00:00:00Z",
        "source_epoch": 1790294400,
        "source_arch_snapshot": {
            "id": "arch-2026-09-24T000000Z-000000000000",
            "archive_date": "2026/09/24",
            "database_hashes": {"core.db": digest},
        },
        "channel": channel,
        "repositories": [
            {
                "name": "kitpro-0.1-dev-core",
                "architecture": "x86_64",
                "database": {
                    "filename": "kitpro-0.1-dev-core.db.tar.gz",
                    "sha256": digest,
                    "object_sha256": digest,
                    "signature_filename": "kitpro-0.1-dev-core.db.tar.gz.sig",
                    "signature_sha256": digest,
                    "signature_object_sha256": digest,
                    "signer_fingerprint": "B" * 40,
                    "files_filename": "kitpro-0.1-dev-core.files.tar.gz",
                    "files_sha256": digest,
                    "files_object_sha256": digest,
                },
                "packages": [package("base")],
            }
        ],
        "promotion_history": [],
        "previous_generation": None,
        "signing": {"development_only": True, "roles": {}},
        "validation": {"status": "passed", "checks": []},
        "known_exceptions": [],
    }


class PackageSetTests(unittest.TestCase):
    def test_declared_package_set_is_valid(self) -> None:
        document = json.loads((ROOT / "config/package-set.json").read_text())
        kitpro_repo.validate_package_set(document)

    def test_admin_baseline_tools_are_explicit_product_dependencies(self) -> None:
        document = json.loads((ROOT / "config/package-set.json").read_text())
        explicit = {entry["name"] for entry in document["explicit_packages"]}
        required = {
            "nano",
            "vim",
            "bash-completion",
            "less",
            "which",
            "man-db",
            "man-pages",
            "rsync",
            "jq",
            "bind",
            "tcpdump",
            "dmidecode",
            "smartmontools",
            "nvme-cli",
            "strace",
        }
        self.assertLessEqual(required, explicit)

    def test_package_set_rejects_duplicate_package(self) -> None:
        document = json.loads((ROOT / "config/package-set.json").read_text())
        document["explicit_packages"].append(copy.deepcopy(document["explicit_packages"][0]))
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "duplicate explicit package"):
            kitpro_repo.validate_package_set(document)

    def test_package_set_rejects_foreign_native_namespace(self) -> None:
        document = json.loads((ROOT / "config/package-set.json").read_text())
        document["native_packages"].append("kitpro-server")
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "namespace"):
            kitpro_repo.validate_package_set(document)


class ManifestTests(unittest.TestCase):
    def test_valid_manifest(self) -> None:
        kitpro_repo.validate_manifest(manifest())

    def test_manifest_rejects_missing_field(self) -> None:
        document = manifest()
        del document["source_arch_snapshot"]
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "misses fields"):
            kitpro_repo.validate_manifest(document)

    def test_manifest_rejects_cross_release_generation(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "does not match"):
            kitpro_repo.validate_manifest(manifest(generation="0.2-dev-g0001"))

    def test_manifest_rejects_incomplete_dependency_closure(self) -> None:
        document = manifest()
        document["repositories"][0]["packages"][0]["dependencies"] = ["missing-lib>=1"]
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "dependency closure"):
            kitpro_repo.validate_manifest(document)

    def test_virtual_provision_satisfies_dependency(self) -> None:
        document = manifest()
        document["repositories"][0]["packages"][0]["dependencies"] = ["virtual-feature=1"]
        provider = package("provider")
        provider["provides"] = ["virtual-feature=1"]
        document["repositories"][0]["packages"].append(provider)
        kitpro_repo.validate_manifest(document)


class RepositoryStateTests(unittest.TestCase):
    def test_normalized_database_has_pacman_compatible_member_names(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "source"
            (source / "example-1-1").mkdir(parents=True)
            (source / "example-1-1/desc").write_text("%NAME%\nexample\n")
            database = root / "repository.db.tar.gz"
            with tarfile.open(database, "w:gz") as archive:
                archive.add(source / "example-1-1", arcname="./example-1-1")
            kitpro_repo.normalize_tar_gz(database, 1790294400)
            listing = subprocess.run(
                ["bsdtar", "-tf", str(database)],
                check=True,
                text=True,
                capture_output=True,
            ).stdout.splitlines()
            self.assertIn("example-1-1/desc", listing)
            self.assertFalse(any(item.startswith("./") for item in listing))

    def test_generation_must_be_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "0.1-dev-g0002").mkdir()
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "greater"):
                kitpro_repo.ensure_generation_monotonic("0.1-dev", "0.1-dev-g0001", root)

    def test_existing_generation_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "0.1-dev-g0001").mkdir()
            kitpro_repo.ensure_generation_monotonic("0.1-dev", "0.1-dev-g0001", root)

    def test_object_store_detects_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "input"
            source.write_bytes(b"known bytes")
            digest = kitpro_repo.add_object(root, source)
            stored = kitpro_repo.object_path(root, digest)
            os.chmod(stored, 0o644)
            stored.write_bytes(b"corrupt")
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "corrupt"):
                kitpro_repo.add_object(root, source)

    def test_materialization_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / "input"
            source.write_bytes(b"artifact")
            digest = kitpro_repo.add_object(root, source)
            destination = root / "edge/package"
            kitpro_repo.materialize_object(root, digest, destination)
            kitpro_repo.materialize_object(root, digest, destination)
            self.assertTrue(destination.is_symlink())
            self.assertEqual(kitpro_repo.sha256_file(destination), digest)

    def test_current_pointer_is_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "0.1-dev-g0001").mkdir()
            kitpro_repo.set_current(root, "0.1-dev-g0001")
            kitpro_repo.set_current(root, "0.1-dev-g0001")
            self.assertEqual(os.readlink(root / "current"), "0.1-dev-g0001")

    def test_promotion_direction_is_enforced(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported promotion"):
            kitpro_repo.promote("0.1-dev", Path("/nonexistent"), Path("/nonexistent"), "testing", "edge")


class SecretScannerTests(unittest.TestCase):
    def test_private_key_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "innocent.txt"
            path.write_bytes(b"-----BEGIN PGP " + b"PRIVATE KEY BLOCK-----")
            self.assertTrue(check_tracked_secrets.violations([path], root))

    def test_public_key_text_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "public.asc"
            path.write_bytes(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
            self.assertEqual(check_tracked_secrets.violations([path], root), [])


if __name__ == "__main__":
    unittest.main()
