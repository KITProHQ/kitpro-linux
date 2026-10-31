from __future__ import annotations

import base64
import copy
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import generation_descriptor, kitpro_repo


def records(root: Path) -> list[dict]:
    result = []
    for index, (name, version) in enumerate(
        (("example", "1.0-1"), ("kitpro-linux-release", "1.1.0-5"))
    ):
        filename = f"{name}-{version}-any.pkg.tar.zst"
        signature_filename = f"{filename}.sig"
        (root / filename).write_bytes(f"package:{name}\n".encode())
        (root / signature_filename).write_bytes(f"signature:{name}\n".encode())
        result.append(
            {
                "name": name,
                "version": version,
                "explicit": index == 1,
                "filename": filename,
                "sha256": kitpro_repo.sha256_file(root / filename),
                "signature_filename": signature_filename,
                "signature_sha256": kitpro_repo.sha256_file(root / signature_filename),
                "signer_fingerprint": "A" * 40,
            }
        )
    return result


def descriptor(packages: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "release": "1.1",
        "generation_id": "1.1-g0001",
        "repository": "kitpro-1.1-core",
        "generation_manifest_sha256": "1" * 64,
        "signing_payload_sha256": "2" * 64,
        "inventory_sha256": "3" * 64,
        "package_count": len(packages),
        "explicit_package_count": 1,
        "packages": [
            {
                "name": item["name"],
                "version": item["version"],
                "explicit": item["explicit"],
            }
            for item in packages
        ],
    }


def write_database(
    path: Path,
    packages: list[dict],
    value: dict | None,
    *,
    member: str = "kitpro-linux-release-1.1.0-5/kitpro-generation.json",
    duplicate: bool = False,
    malformed: bool = False,
    extra_member: str | None = None,
) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for package in packages:
            parent = f"{package['name']}-{package['version']}"
            directory = tarfile.TarInfo(parent)
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            signature = (path.parent / package["signature_filename"]).read_bytes()
            data = (
                f"%NAME%\n{package['name']}\n\n"
                f"%VERSION%\n{package['version']}\n\n"
                f"%FILENAME%\n{package['filename']}\n\n"
                f"%SHA256SUM%\n{package['sha256']}\n\n"
                f"%PGPSIG%\n{base64.b64encode(signature).decode()}\n"
            ).encode()
            info = tarfile.TarInfo(f"{parent}/desc")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if value is not None:
            data = b"{" if malformed else kitpro_repo.canonical_json_bytes(value)
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
            if duplicate:
                archive.addfile(info, io.BytesIO(data))
        if extra_member:
            data = b"unexpected"
            info = tarfile.TarInfo(extra_member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class GenerationDescriptorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.packages = records(self.root)
        self.member = generation_descriptor.descriptor_member("1.1.0-5")
        self.value = descriptor(self.packages)
        self.database = self.root / "kitpro-1.1-core.db.tar.gz"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self) -> dict:
        return generation_descriptor.validate_database(
            self.database,
            expected_member=self.member,
            expected_descriptor=self.value,
            packages=self.packages,
            package_directory=self.root,
        )

    def test_valid_descriptor_and_package_database_are_accepted(self) -> None:
        write_database(self.database, self.packages, self.value)
        self.assertEqual(self.validate()["package_count"], 2)

    def test_missing_duplicate_and_malformed_descriptors_are_rejected(self) -> None:
        for value, duplicate, malformed in (
            (None, False, False),
            (self.value, True, False),
            (self.value, False, True),
        ):
            with self.subTest(value=value, duplicate=duplicate, malformed=malformed):
                write_database(
                    self.database,
                    self.packages,
                    value,
                    duplicate=duplicate,
                    malformed=malformed,
                )
                with self.assertRaises(kitpro_repo.PipelineError):
                    self.validate()

    def test_wrong_descriptor_bindings_are_rejected(self) -> None:
        for field, wrong in (
            ("generation_id", "1.1-g0002"),
            ("release", "1.0"),
            ("repository", "kitpro-1.0-core"),
            ("generation_manifest_sha256", "4" * 64),
            ("inventory_sha256", "5" * 64),
        ):
            changed = copy.deepcopy(self.value)
            changed[field] = wrong
            with self.subTest(field=field):
                write_database(self.database, self.packages, changed)
                with self.assertRaisesRegex(kitpro_repo.PipelineError, "approved contract"):
                    self.validate()

    def test_modified_package_identity_is_rejected(self) -> None:
        changed = copy.deepcopy(self.packages)
        changed[0]["sha256"] = "0" * 64
        write_database(self.database, changed, self.value)
        with self.assertRaises(kitpro_repo.PipelineError):
            self.validate()

    def test_archive_member_manipulation_is_rejected(self) -> None:
        write_database(
            self.database,
            self.packages,
            self.value,
            extra_member="unexpected/file",
        )
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported"):
            self.validate()

    def test_valid_signature_does_not_override_invalid_semantics(self) -> None:
        changed = copy.deepcopy(self.value)
        changed["generation_id"] = "1.1-g0002"
        write_database(self.database, self.packages, changed)
        signature = self.root / "database.sig"
        signature.write_bytes(b"cryptographically-valid-for-test")
        with (
            patch.object(kitpro_repo, "verify_signature", return_value="B" * 40),
            self.assertRaisesRegex(kitpro_repo.PipelineError, "approved contract"),
        ):
            generation_descriptor.validate_signed_database(
                self.database,
                signature,
                public_home=self.root,
                expected_signer="B" * 40,
                expected_member=self.member,
                expected_descriptor=self.value,
                packages=self.packages,
                package_directory=self.root,
            )

    def test_embedding_is_deterministic_and_refuses_existing_descriptor(self) -> None:
        write_database(self.database, self.packages, None)
        generation_descriptor.embed_descriptor(
            self.database,
            member_name=self.member,
            descriptor=self.value,
            source_epoch=1793401705,
        )
        first = self.database.read_bytes()
        self.validate()
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "already contains"):
            generation_descriptor.embed_descriptor(
                self.database,
                member_name=self.member,
                descriptor=self.value,
                source_epoch=1793401705,
            )
        copy_path = self.root / "copy.db.tar.gz"
        write_database(copy_path, self.packages, None)
        generation_descriptor.embed_descriptor(
            copy_path,
            member_name=self.member,
            descriptor=self.value,
            source_epoch=1793401705,
        )
        self.assertEqual(first, copy_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
