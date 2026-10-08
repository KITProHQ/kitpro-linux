from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install.disk import create_test_disk
from tools.install.model import ABSOLUTE_MINIMUM_BYTES, parse_spec
from tools.install.plan import build_plan, validate_plan
from tests.plan_fixture import generation_fixture


ROOT = Path(__file__).resolve().parents[1]


def document(target: Path) -> dict[str, object]:
    return {
        "version": 1,
        "release": {"name": "0.1-dev", "generation": "0.1-dev-g0010"},
        "system": {"hostname": "plan-test"},
        "disk": {"device": str(target), "target_type": "image"},
        "administrator": {"username": "plan-admin", "ssh_authorized_keys": []},
        "ssh": {"enabled": False},
    }


class InstallPlanTests(unittest.TestCase):
    def test_schema_is_valid_json(self) -> None:
        json.loads((ROOT / "schemas/install-plan.schema.json").read_text())

    def test_plan_is_deterministic_and_pins_active_generation(self) -> None:
        with generation_fixture(), tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            spec = parse_spec(document(target))
            first = build_plan(spec)
            second = build_plan(spec)
            self.assertEqual(first, second)
            self.assertEqual(first["repository_generation"], "0.1-dev-g0010")
            self.assertEqual(first["repository"]["package_count"], 199)
            self.assertEqual(first["partition_table"]["type"], "gpt")
            self.assertEqual(first["partition_table"]["esp"]["size_bytes"], 256 * 1024**2)
            self.assertGreaterEqual(first["rootfs"]["planned_free_reserve_bytes"], 2 * 1024**3)

    def test_plan_hash_detects_mutation(self) -> None:
        with generation_fixture(), tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            plan = build_plan(parse_spec(document(target)))
            changed = copy.deepcopy(plan)
            changed["system"]["hostname"] = "changed"
            with self.assertRaisesRegex(kitpro_repo.PipelineError, "hash"):
                validate_plan(changed)

    def test_missing_generation_fails_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            value = document(target)
            value["release"] = {"name": "0.1-dev", "generation": "0.1-dev-g9999"}
            with (
                mock.patch(
                    "tools.install.plan._generation",
                    side_effect=kitpro_repo.PipelineError(
                        "pinned Stable generation is unavailable: 0.1-dev-g9999"
                    ),
                ),
                self.assertRaisesRegex(kitpro_repo.PipelineError, "unavailable"),
            ):
                build_plan(parse_spec(value))

    def test_invalid_repository_signature_fails_before_install(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = Path(name) / "disk.raw"
            create_test_disk(target, ABSOLUTE_MINIMUM_BYTES)
            with mock.patch(
                "tools.install.plan._generation",
                side_effect=kitpro_repo.PipelineError("invalid repository signature"),
            ):
                with self.assertRaisesRegex(kitpro_repo.PipelineError, "invalid repository signature"):
                    build_plan(parse_spec(document(target)))


if __name__ == "__main__":
    unittest.main()
