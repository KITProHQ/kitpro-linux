from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools import kitpro_repo
from tools.install.model import ABSOLUTE_MINIMUM_BYTES, parse_spec


ROOT = Path(__file__).resolve().parents[1]


def valid_document() -> dict[str, object]:
    return {
        "version": 1,
        "release": {"name": "0.1-dev", "generation": "0.1-dev-g0002"},
        "system": {"hostname": "kitpro"},
        "disk": {"device": "/tmp/kitpro-target.raw"},
        "administrator": {
            "username": "kitpro-admin",
            "ssh_authorized_keys": ["ssh-ed25519 AAAAC3NzaValidFixture test"],
        },
        "ssh": {"enabled": True},
    }


class InstallSchemaTests(unittest.TestCase):
    def test_example_and_schema_are_valid_json(self) -> None:
        json.loads((ROOT / "schemas/install-spec-v1.schema.json").read_text())
        parse_spec(json.loads((ROOT / "config/install.example.json").read_text()))

    def test_defaults_are_explicit_in_normalized_spec(self) -> None:
        spec = parse_spec(valid_document())
        self.assertEqual(spec.system.locale, "C.UTF-8")
        self.assertEqual(spec.system.timezone, "UTC")
        self.assertEqual(spec.network.mode, "dhcp")
        self.assertEqual(spec.disk.minimum_capacity_bytes, ABSOLUTE_MINIMUM_BYTES)
        self.assertTrue(spec.firewall.ssh)

    def test_unknown_field_is_rejected(self) -> None:
        document = valid_document()
        document["password"] = "secret"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported fields"):
            parse_spec(document)

    def test_unsupported_version_is_rejected(self) -> None:
        document = valid_document()
        document["version"] = 2
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported.*version"):
            parse_spec(document)

    def test_static_network_requires_complete_ipv4_configuration(self) -> None:
        document = valid_document()
        document["network"] = {"mode": "static", "address": "10.0.2.15", "prefix": 24}
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "requires address and gateway"):
            parse_spec(document)

    def test_static_network_rejects_invalid_addresses(self) -> None:
        document = valid_document()
        document["network"] = {
            "mode": "static", "address": "999.0.2.15", "prefix": 24,
            "gateway": "10.0.2.2", "dns": ["10.0.2.3"],
        }
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "invalid static IPv4"):
            parse_spec(document)

    def test_ssh_requires_key_and_matching_firewall(self) -> None:
        document = valid_document()
        document["administrator"] = {"username": "kitpro-admin", "ssh_authorized_keys": []}
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "SSH requires"):
            parse_spec(document)
        document = valid_document()
        document["firewall"] = {"ssh": False}
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "must match"):
            parse_spec(document)

    def test_plaintext_password_fields_cannot_be_expressed(self) -> None:
        document = copy.deepcopy(valid_document())
        document["administrator"]["password"] = "secret"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "unsupported fields"):
            parse_spec(document)

    def test_yescrypt_hash_is_the_only_supported_unattended_password_form(self) -> None:
        document = copy.deepcopy(valid_document())
        value = "$y$j9T$abcdefghijklmnop$" + "a" * 43
        document["administrator"]["password_hash"] = value
        spec = parse_spec(document)
        self.assertEqual(spec.administrator.password_hash, value)
        self.assertNotIn("password", spec.to_dict()["administrator"])
        document["administrator"]["password_hash"] = "plaintext"
        with self.assertRaisesRegex(kitpro_repo.PipelineError, "yescrypt"):
            parse_spec(document)

    def test_normalized_spec_hash_is_deterministic(self) -> None:
        first = parse_spec(valid_document())
        second = parse_spec(copy.deepcopy(valid_document()))
        self.assertEqual(first.sha256(), second.sha256())


if __name__ == "__main__":
    unittest.main()
