from __future__ import annotations

import copy
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tools import check_tracked_secrets
from tools import kitpro_repo


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT / "repo"
STATE_ROOT = ROOT / ".state"
RELEASE = "0.1-dev"
GENERATION = "0.1-dev-g0001"


@unittest.skipUnless(
    os.environ.get("KITPRO_PHASE1_ACCEPTANCE") == "1",
    "set KITPRO_PHASE1_ACCEPTANCE=1 after generating the local repository proof",
)
class Phase1AcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key_state = STATE_ROOT / "dev-keys"
        cls.roots = {
            "edge": REPO_ROOT / "edge",
            "testing": REPO_ROOT / "testing",
            "stable": REPO_ROOT / "stable" / RELEASE / GENERATION,
        }
        cls.manifests = {
            channel: json.loads((root / "manifest.json").read_text())
            for channel, root in cls.roots.items()
        }

    def test_generation_manifests_validate(self) -> None:
        schema = json.loads((ROOT / "schemas/generation-manifest.schema.json").read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        for manifest in self.manifests.values():
            kitpro_repo.validate_manifest(manifest)

    def test_all_published_hashes_and_signatures_verify(self) -> None:
        for channel, manifest in self.manifests.items():
            kitpro_repo.verify_manifest_artifacts(
                manifest,
                REPO_ROOT,
                self.roots[channel],
                self.key_state,
            )

    def test_missing_artifact_is_rejected(self) -> None:
        broken = copy.deepcopy(self.manifests["stable"])
        broken["repositories"][0]["packages"][0]["sha256"] = "0" * 64
        broken["repositories"][0]["packages"][0]["object_sha256"] = "0" * 64
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "missing or corrupt"):
            kitpro_repo.verify_manifest_artifacts(
                broken,
                REPO_ROOT,
                self.roots["stable"],
                self.key_state,
            )

    def test_upstream_signatures_accept_and_tamper_rejects(self) -> None:
        manifest = self.manifests["stable"]
        archive_date = manifest["source_arch_snapshot"]["archive_date"].replace("/", "-")
        arch_keyring = STATE_ROOT / "ingest" / archive_date / "arch-gnupg"
        upstream = [
            package
            for package in manifest["repositories"][0]["packages"]
            if package["origin_type"] == "upstream-binary"
        ]
        for package in upstream:
            signature = package["upstream_signature"]
            signer = kitpro_repo.verify_signature(
                arch_keyring,
                kitpro_repo.object_path(REPO_ROOT, signature["object_sha256"]),
                kitpro_repo.object_path(REPO_ROOT, package["object_sha256"]),
            )
            self.assertEqual(signer, signature["signer_fingerprint"])
        with tempfile.TemporaryDirectory() as name:
            invalid = Path(name) / "invalid.sig"
            first_signature = kitpro_repo.object_path(
                REPO_ROOT,
                upstream[0]["upstream_signature"]["object_sha256"],
            )
            data = bytearray(first_signature.read_bytes())
            data[len(data) // 2] ^= 1
            invalid.write_bytes(data)
            with self.assertRaises(kitpro_repo.PipelineError):
                kitpro_repo.verify_signature(
                    arch_keyring,
                    invalid,
                    kitpro_repo.object_path(REPO_ROOT, upstream[0]["object_sha256"]),
                )

    def test_dependency_closure_is_complete(self) -> None:
        kitpro_repo.validate_dependency_closure(self.manifests["stable"])

    def test_promotion_preserves_all_artifact_references(self) -> None:
        def references(document: dict[str, object]) -> set[str]:
            return kitpro_repo.manifest_object_hashes(document)

        self.assertEqual(references(self.manifests["edge"]), references(self.manifests["testing"]))
        self.assertEqual(references(self.manifests["testing"]), references(self.manifests["stable"]))

    def test_stable_generation_and_archive_are_not_writable(self) -> None:
        targets = [
            self.roots["stable"],
            REPO_ROOT / "archive" / RELEASE / GENERATION,
        ]
        for target in targets:
            for path in [target, *target.rglob("*")]:
                if path.is_symlink():
                    continue
                writable = path.stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
                self.assertEqual(writable, 0, str(path))
        with self.assertRaises(PermissionError):
            self.roots["stable"].joinpath("manifest.json").open("ab")

    def test_database_signature_is_valid(self) -> None:
        manifest = self.manifests["stable"]
        repository = manifest["repositories"][0]
        database = repository["database"]
        repository_dir = self.roots["stable"] / "core/os/x86_64"
        signer = kitpro_repo.verify_signature(
            self.key_state / "repository",
            repository_dir / database["signature_filename"],
            repository_dir / database["filename"],
        )
        self.assertEqual(signer, database["signer_fingerprint"])

    def test_reconstruction_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            report = kitpro_repo.reconstruct(
                RELEASE,
                GENERATION,
                REPO_ROOT,
                self.key_state,
                Path(name) / "repository",
            )
        self.assertEqual(report["result"], "passed")
        self.assertEqual(report["package_hash_mismatches"], [])
        self.assertTrue(report["repository_database"]["identical"])
        self.assertTrue(report["files_database"]["identical"])

    def test_current_targets_latest_published_generation(self) -> None:
        current = REPO_ROOT / "stable" / RELEASE / "current"
        self.assertTrue(current.is_symlink())
        generations = sorted(
            path.name
            for path in (REPO_ROOT / "stable" / RELEASE).glob(f"{RELEASE}-g[0-9][0-9][0-9][0-9]")
        )
        self.assertEqual(os.readlink(current), generations[-1])

    def test_cross_release_promotion_is_rejected(self) -> None:
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "cross-release"):
            kitpro_repo.promote("0.2-dev", REPO_ROOT, self.key_state, "edge", "testing")

    def test_isolated_strict_client_consumes_repository(self) -> None:
        config = kitpro_repo.render_client_config(
            REPO_ROOT, RELEASE, STATE_ROOT, self.key_state
        )
        kitpro_repo.run(["fakeroot", "pacman", "-Sy", "--noconfirm", "--config", str(config)])
        resolution = kitpro_repo.run(
            [
                "pacman", "-Sp", "--config", str(config), "--print-format",
                "%n|%v|%r", "kitpro-linux-base",
            ]
        )
        self.assertIn("kitpro-linux-base", resolution.stdout)

    def test_no_private_key_material_is_tracked(self) -> None:
        self.assertEqual(check_tracked_secrets.violations(check_tracked_secrets.tracked_paths()), [])


if __name__ == "__main__":
    unittest.main()
