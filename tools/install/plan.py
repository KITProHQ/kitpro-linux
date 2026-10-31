"""Environmental boundary for the pure KITPro installation planner."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from kitpro_install_planner import (
    PlanningError,
    PlanningRequestV1,
    PlanningResultV1,
    SourceFactsV1,
    plan_v1,
    validate_plan_document,
)
from kitpro_install_planner.inventory import StorageEligibility
from tools import kitpro_repo
from tools.install import INSTALLER_VERSION
from tools.install.disk import DiskState, discover_disk
from tools.install.model import InstallSpec

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT / "repo"
KEY_ROOT = PROJECT_ROOT / ".state/dev-keys"
ROOTFS_PROFILE = PROJECT_ROOT / "config/install-rootfs-profile.json"


def _generation(spec: InstallSpec) -> tuple[Path, dict[str, Any]]:
    """Verify and return the pinned source at the privileged trust boundary."""
    if spec.release.name == "1.0":
        from tools.install import production

        return production.verify(spec.release.generation, REPO_ROOT)
    root = REPO_ROOT / "stable" / spec.release.name / spec.release.generation
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise kitpro_repo.PipelineError(
            f"pinned Stable generation is unavailable: {spec.release.generation}"
        )
    manifest = kitpro_repo.load_json(manifest_path)
    kitpro_repo.validate_manifest(manifest)
    if (
        manifest["release"] != spec.release.name
        or manifest["generation_id"] != spec.release.generation
    ):
        raise kitpro_repo.PipelineError("pinned Stable generation metadata does not match the spec")
    kitpro_repo.verify_manifest_artifacts(manifest, REPO_ROOT, root, KEY_ROOT)
    return root, manifest


def _request(spec: InstallSpec, disk: DiskState) -> PlanningRequestV1:
    """Collect verified filesystem facts, then cross into the pure API."""
    generation_root, manifest = _generation(spec)
    production = spec.release.name == "1.0"
    package_count = (
        manifest["package_count"]
        if production
        else sum(len(repository["packages"]) for repository in manifest["repositories"])
    )
    profile = kitpro_repo.load_json(ROOTFS_PROFILE)
    if profile["release"] != spec.release.name or profile["generation"] != spec.release.generation:
        raise kitpro_repo.PipelineError(
            "rootfs profile does not match the pinned Stable generation"
        )
    if production and sorted(profile["explicit_packages"]) != sorted(
        package["name"] for package in manifest["packages"] if package["explicit"]
    ):
        raise kitpro_repo.PipelineError("production profile differs from frozen explicit inventory")
    return PlanningRequestV1(
        install_spec=spec.to_dict(),
        target=disk.to_dict(),
        source=SourceFactsV1(
            release=spec.release.name,
            generation=spec.release.generation,
            generation_manifest_sha256=kitpro_repo.sha256_file(generation_root / "manifest.json"),
            artifact_set_sha256=(
                manifest["artifact_set_sha256"]
                if production
                else kitpro_repo.manifest_artifact_hash(manifest)
            ),
            package_count=package_count,
            source=str(generation_root.relative_to(PROJECT_ROOT)),
            rootfs_profile_sha256=kitpro_repo.sha256_file(ROOTFS_PROFILE),
        ),
        installer_version=INSTALLER_VERSION,
    )


def build_planning_result(spec: InstallSpec) -> PlanningResultV1:
    """Discover and verify environmental inputs, then build the pure result."""
    disk = discover_disk(
        Path(spec.disk.device), spec.disk.target_type, spec.disk.minimum_capacity_bytes
    )
    try:
        return plan_v1(_request(spec, disk))
    except PlanningError as error:
        raise kitpro_repo.PipelineError(str(error)) from error


def build_plan(spec: InstallSpec) -> dict[str, Any]:
    """Return the unchanged schema-v1 document consumed by the execution layer."""
    return build_planning_result(spec).plan


def validate_plan(document: dict[str, Any]) -> None:
    try:
        validate_plan_document(document)
    except PlanningError as error:
        raise kitpro_repo.PipelineError(str(error)) from error


def load_plan(path: Path) -> dict[str, Any]:
    document = kitpro_repo.load_json(path)
    if not isinstance(document, dict):
        raise kitpro_repo.PipelineError("install plan must be a JSON object")
    validate_plan(document)
    return document


def plan_disk_state(document: dict[str, Any]) -> DiskState:
    value = document["target"]
    return DiskState(
        path=value["path"],
        target_type=value["target_type"],
        size_bytes=value["size_bytes"],
        identity=value["identity"],
        mounted_paths=tuple(value["mounted_paths"]),
        signatures=tuple(value["signatures"]),
        partition_table=value["partition_table"],
        marker_sha256=value.get("marker_sha256"),
        partitions=tuple(value.get("partitions", ())),
        transport=value.get("transport"),
        read_only=value.get("read_only"),
        stable_ids=tuple(value.get("stable_ids", ())),
        protection_reasons=tuple(value.get("protection_reasons", ())),
        observation_errors=tuple(value.get("observation_errors", ())),
        eligibility=StorageEligibility(
            eligible=value["eligibility"]["eligible"],
            requires_destructive_confirmation=value["eligibility"][
                "requires_destructive_confirmation"
            ],
            rejection_reasons=tuple(value["eligibility"]["rejection_reasons"]),
        ),
    )
