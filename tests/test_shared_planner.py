from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from dataclasses import replace
from unittest import mock

import pytest

from kitpro_install_planner import (
    API_VERSION,
    KITPRO_LINUX_1_0_SOURCE,
    PlanningError,
    PlanningRequestV1,
    SourceFactsV1,
    canonical_json_bytes,
    plan_v1,
)
from tests.plan_fixture import generation_fixture
from tools.install import INSTALLER_VERSION, production
from tools.install.disk import DiskState
from tools.install.model import parse_spec
from tools.install.plan import build_plan, build_planning_result

GIB = 1024**3
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaSharedPlannerFixture operator"


def spec_document(*, static: bool = False, ssh: bool = False) -> dict[str, object]:
    network: dict[str, object] = {"mode": "dhcp"}
    if static:
        network = {
            "mode": "static",
            "address": "192.0.2.10",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "dns": ["192.0.2.53", "198.51.100.53"],
        }
    return {
        "version": 1,
        "release": {"name": "0.1-dev", "generation": "0.1-dev-g0010"},
        "system": {"hostname": "shared-plan", "locale": "C.UTF-8", "timezone": "UTC"},
        "disk": {
            "device": "/dev/vda",
            "target_type": "block",
            "layout": "standard",
            "filesystem": "ext4",
            "minimum_capacity_gib": 6,
        },
        "network": network,
        "administrator": {
            "username": "kitpro-admin",
            "ssh_authorized_keys": [PUBLIC_KEY] if ssh else [],
        },
        "ssh": {"enabled": ssh},
        "firewall": {"ssh": ssh},
        "boot": {"mode": "uefi"},
    }


def disk() -> DiskState:
    return DiskState(
        path="/dev/vda",
        target_type="block",
        size_bytes=8 * GIB,
        identity={"model": "Fixture", "serial": "SHARED-1", "wwn": None},
        mounted_paths=(),
        signatures=(),
        partition_table="unknown",
        marker_sha256=None,
    )


def pure_request(*, static: bool = False, ssh: bool = False) -> PlanningRequestV1:
    spec = parse_spec(spec_document(static=static, ssh=ssh))
    return PlanningRequestV1(
        install_spec=spec.to_dict(),
        target=disk().to_dict(),
        source=SourceFactsV1(
            release="0.1-dev",
            generation="0.1-dev-g0010",
            generation_manifest_sha256="a" * 64,
            artifact_set_sha256="b" * 64,
            package_count=199,
            source="repo/stable/0.1-dev/0.1-dev-g0010",
            rootfs_profile_sha256="c" * 64,
        ),
        installer_version=INSTALLER_VERSION,
    )


@pytest.mark.parametrize(
    ("layout", "roles"),
    [
        ("separate-home", ["esp", "root", "home"]),
        ("root-swap", ["esp", "root", "swap"]),
        ("root-home-swap", ["esp", "root", "home", "swap"]),
    ],
)
def test_shared_planner_emits_authoritative_custom_storage_operations(
    layout: str, roles: list[str]
) -> None:
    document = spec_document()
    document["disk"]["layout"] = layout
    document["disk"]["storage"] = {
        "schema_version": 1,
        "layout": layout,
        "root_size_bytes": 5 * GIB if "home" in layout else None,
        "swap_size_bytes": GIB // 2 if "swap" in layout else None,
        "logical_sector_bytes": 512,
        "physical_sector_bytes": 4096,
    }
    parsed = parse_spec(document)
    request = pure_request()
    result = plan_v1(
        PlanningRequestV1(
            install_spec=parsed.to_dict(),
            target=request.target,
            source=request.source,
            installer_version=request.installer_version,
        )
    )
    table = result.plan["partition_table"]
    assert [item["role"] for item in table["partitions"]] == roles
    assert table["storage_schema_version"] == 1
    assert result.plan["boot"]["root_identifier"] == (f"PARTUUID={table['root']['partition_uuid']}")
    operation_ids = [item["id"] for item in result.operations]
    assert ("create-home" in operation_ids) == ("home" in roles)
    assert ("create-swap" in operation_ids) == ("swap" in roles)


@pytest.mark.parametrize(
    ("static", "ssh", "expected_plan_sha256"),
    [
        (False, False, "c5f3456b0d0439e874e031ab020df0599992897f9f7a0d3b003d98a868540e45"),
        (True, False, "d700cc47fa61f076a9522dff3dbd7029bd2ed07a950d7db729be110f0590ec3d"),
        (False, True, "6898fe4c6d56127b93102ba7aa7486a56a667aae00095ab32d13784c4764d608"),
    ],
)
def test_pure_result_is_complete_and_deterministic(
    static: bool, ssh: bool, expected_plan_sha256: str
) -> None:
    request = pure_request(static=static, ssh=ssh)
    first = plan_v1(request)
    second = plan_v1(request)
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.result_sha256 == second.result_sha256
    assert [operation["order"] for operation in first.operations] == list(range(1, 14))
    assert all(operation["arguments"] for operation in first.operations)
    assert first.plan["plan_sha256"] == expected_plan_sha256
    first.validate()


def test_api_and_contract_versions_fail_closed() -> None:
    with pytest.raises(PlanningError, match="API version"):
        plan_v1(replace(pure_request(), api_version=API_VERSION + 1))
    request = pure_request()
    unsupported = copy.deepcopy(dict(request.install_spec))
    unsupported["version"] = 2
    with pytest.raises(PlanningError, match="specification version"):
        plan_v1(
            PlanningRequestV1(
                install_spec=unsupported,
                target=request.target,
                source=request.source,
                installer_version=request.installer_version,
            )
        )


def test_import_and_planning_need_no_filesystem_network_or_process_access() -> None:
    request = pure_request(ssh=True)
    with (
        mock.patch("builtins.open", side_effect=AssertionError("filesystem access")),
        mock.patch("socket.socket", side_effect=AssertionError("network access")),
        mock.patch.object(subprocess, "run", side_effect=AssertionError("process access")),
    ):
        result = plan_v1(request)
    assert PUBLIC_KEY not in result.canonical_bytes().decode()
    assert hashlib.sha256(PUBLIC_KEY.encode()).hexdigest() in result.canonical_bytes().decode()


def test_import_does_not_load_installation_engine() -> None:
    completed = subprocess.run(
        [
            "python",
            "-c",
            ("import sys, kitpro_install_planner; print('tools.install.engine' in sys.modules)"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "False"


@pytest.mark.parametrize(("static", "ssh"), [(False, False), (True, False), (False, True)])
def test_existing_entry_point_and_extracted_api_have_full_canonical_equality(
    static: bool, ssh: bool
) -> None:
    spec = parse_spec(spec_document(static=static, ssh=ssh))
    with generation_fixture(), mock.patch("tools.install.plan.discover_disk", return_value=disk()):
        result = build_planning_result(spec)
        document = build_plan(spec)
    assert document == result.plan
    assert canonical_json_bytes(document) == canonical_json_bytes(result.plan)
    assert result.operations[9]["arguments"]["interface_match"] == "en*"
    assert result.operations[10]["arguments"]["ssh"]["enabled"] is ssh


def test_changed_target_and_unsupported_policy_are_rejected() -> None:
    request = pure_request()
    changed_target = dict(request.target)
    changed_target["path"] = "/dev/vdb"
    with pytest.raises(PlanningError, match="does not match"):
        plan_v1(
            PlanningRequestV1(
                install_spec=request.install_spec,
                target=changed_target,
                source=request.source,
                installer_version=request.installer_version,
            )
        )
    unsupported = copy.deepcopy(dict(request.install_spec))
    unsupported["boot"]["mode"] = "bios"
    with pytest.raises(PlanningError, match="boot.mode"):
        plan_v1(
            PlanningRequestV1(
                install_spec=unsupported,
                target=request.target,
                source=request.source,
                installer_version=request.installer_version,
            )
        )


def test_supported_source_facts_match_authoritative_production_pins() -> None:
    source = KITPRO_LINUX_1_0_SOURCE
    manifest_path = production.ROOT / "docs/results/production-generations/1.0-g0002-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert production.PINS[source.generation] == source.generation_manifest_sha256
    assert (
        source.generation_manifest_sha256 == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    )
    assert source.artifact_set_sha256 == manifest["artifact_set_sha256"]
    assert source.package_count == manifest["package_count"]
    assert (
        source.rootfs_profile_sha256
        == hashlib.sha256(
            (production.ROOT / "config/production-install-rootfs-profile.json").read_bytes()
        ).hexdigest()
    )
