"""Read-only bindings from the versioned adapter to authoritative install code."""

from __future__ import annotations

import hmac
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from kitpro_execution_adapter import (
    AdapterError,
    EnvironmentEvidenceV1,
    ExecutionRequestV1,
    RuntimeSecretReference,
    SourceEvidenceV1,
    TargetEvidenceV1,
    public_key_id,
    sha256_document,
    verify_document,
)
from tools import kitpro_repo
from tools.install.disk import assert_disk_unchanged, discover_disk
from tools.install.model import InstallSpec, parse_spec
from tools.install.plan import build_planning_result, validate_plan
from tools.install.rootfs import validate_install_source


class EnvironmentVerifier(Protocol):
    def verify(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1: ...


class SecretBroker(Protocol):
    def available(self, reference: RuntimeSecretReference) -> bool: ...


class UnavailableEnvironmentVerifier:
    def verify(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1:
        del request, target
        raise AdapterError(
            "environment_unavailable",
            "no authorized Phase 3B.2B execution environment is configured",
        )


class UnavailableSecretBroker:
    def available(self, reference: RuntimeSecretReference) -> bool:
        del reference
        return False


class FixtureEnvironmentVerifier:
    """Test-only verifier for explicit marker-owned QEMU fixtures."""

    def __init__(
        self,
        evidence: EnvironmentEvidenceV1,
        *,
        expected_target_identity_sha256: str,
    ) -> None:
        self.evidence = evidence
        self.expected_target_identity_sha256 = expected_target_identity_sha256

    def verify(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1:
        del request
        if not hmac.compare_digest(
            target.identity_sha256,
            self.expected_target_identity_sha256,
        ):
            raise AdapterError(
                "environment_target_mismatch",
                "QEMU ownership evidence does not match the fresh target",
            )
        self.evidence.validate()
        return self.evidence


class SignedQemuEnvironmentVerifier:
    """Verify host-signed file ownership and match it to fresh guest hardware."""

    def __init__(
        self,
        attestation: dict[str, object],
        *,
        public_key_pem: bytes,
        expected_iso_sha256: str,
        guest_disk_inventory: Callable[[], list[dict[str, object]]] | None = None,
        expected_scope: str | None = None,
        expected_authority_role: str | None = None,
        expected_issuer_key_id: str | None = None,
    ) -> None:
        self.attestation = dict(attestation)
        self.public_key_pem = bytes(public_key_pem)
        self.expected_iso_sha256 = expected_iso_sha256
        self.guest_disk_inventory = guest_disk_inventory or discover_guest_install_disks
        self.expected_scope = expected_scope
        self.expected_authority_role = expected_authority_role
        self.expected_issuer_key_id = expected_issuer_key_id
        if self.expected_authority_role is not None and (
            self.attestation.get("authority_role") != self.expected_authority_role
        ):
            raise AdapterError("environment_untrusted", "host attestation authority role changed")
        if self.expected_issuer_key_id is not None and (
            self.attestation.get("issuer_key_id") != self.expected_issuer_key_id
        ):
            raise AdapterError("environment_untrusted", "host attestation key identity changed")
        if self.expected_issuer_key_id is not None and (
            public_key_id(self.public_key_pem) != self.expected_issuer_key_id
        ):
            raise AdapterError(
                "environment_untrusted", "host attestation verifier key identity changed"
            )

    def verify(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1:
        signature = self.attestation.get("signature")
        unsigned = dict(self.attestation)
        unsigned.pop("signature", None)
        if not isinstance(signature, str):
            raise AdapterError("environment_untrusted", "host attestation is unsigned")
        try:
            verify_document(self.public_key_pem, unsigned, signature)
        except AdapterError as error:
            raise AdapterError("environment_untrusted", "host attestation is invalid") from error
        scope = unsigned.get("scope")
        allowed_scopes = {
            "phase3b2c-qualification-only",
            "phase3b2d-qualification-only",
            "phase3b2e-qualification-only",
            "phase3b2f-r1-live-candidate-probe-v1",
            "phase3b2g-workflow-probe-v1",
            "phase3b2e-live-vm-candidate-v1",
        }
        if self.expected_scope is not None and scope != self.expected_scope:
            raise AdapterError("environment_untrusted", "host attestation scope changed")
        live_candidate = scope == "phase3b2e-live-vm-candidate-v1"
        if (
            unsigned.get("schema_version") != 1
            or scope not in allowed_scopes
            or unsigned.get("production_execution_authorized") is not False
            or unsigned.get("writable_launch_permitted") is not live_candidate
        ):
            raise AdapterError("environment_untrusted", "host attestation scope is invalid")
        environment = unsigned.get("environment")
        host_target = unsigned.get("target")
        guest_target = unsigned.get("guest_target")
        if not all(isinstance(value, dict) for value in (environment, host_target, guest_target)):
            raise AdapterError("environment_untrusted", "host attestation fields are invalid")
        assert isinstance(environment, dict)
        assert isinstance(host_target, dict)
        assert isinstance(guest_target, dict)
        expected_guest = {
            "path": target.path,
            "size_bytes": target.size_bytes,
            "virtual_serial": target.identity.get("serial"),
        }
        if guest_target != expected_guest:
            raise AdapterError(
                "environment_target_mismatch", "signed host target differs from guest hardware"
            )
        if scope in {
            "phase3b2d-qualification-only",
            "phase3b2e-qualification-only",
            "phase3b2e-live-vm-candidate-v1",
            "phase3b2g-workflow-probe-v1",
        }:
            signed_inventory = unsigned.get("guest_disk_inventory")
            current_inventory = self.guest_disk_inventory()
            if not isinstance(signed_inventory, list) or signed_inventory != current_inventory:
                raise AdapterError(
                    "environment_disk_inventory_changed",
                    "guest disk inventory differs from signed host evidence",
                )
            if len(current_inventory) != 1 or current_inventory[0].get("path") != target.path:
                raise AdapterError(
                    "environment_unexpected_disk",
                    "execution environment contains an unexpected installation disk",
                )
        if (
            host_target.get("size_bytes") != target.size_bytes
            or host_target.get("virtual_serial") != target.identity.get("serial")
            or environment.get("iso_sha256") != self.expected_iso_sha256
        ):
            raise AdapterError(
                "environment_target_mismatch", "host ownership does not bind the guest target"
            )
        planned_target = request.plan.get("plan", {}).get("target", {})
        if (
            planned_target.get("path") != target.path
            or planned_target.get("size_bytes") != target.size_bytes
            or planned_target.get("identity") != target.identity
        ):
            raise AdapterError("environment_target_mismatch", "plan target differs from hardware")
        profiles = {
            "phase3b2c-qualification-only": "kitpro-phase3b2c-qemu-v1",
            "phase3b2d-qualification-only": "kitpro-phase3b2d-qemu-v1",
            "phase3b2e-qualification-only": "kitpro-phase3b2e-qemu-v1",
            "phase3b2f-r1-live-candidate-probe-v1": "kitpro-phase3b2e-qemu-v1",
            "phase3b2g-workflow-probe-v1": "kitpro-phase3b2e-qemu-v1",
            "phase3b2e-live-vm-candidate-v1": "kitpro-phase3b2e-qemu-v1",
        }
        evidence = EnvironmentEvidenceV1(
            "kitpro-qemu-environment-verifier-v1",
            profiles[str(scope)],
            str(environment["iso_sha256"]),
            sha256_document(unsigned),
            sha256_document(host_target),
        )
        evidence.validate()
        return evidence


class PhysicalConsoleEnvironmentVerifier:
    """Bind a physical install to exact boot media and protected media devices."""

    _HEX64 = re.compile(r"[0-9a-f]{64}")

    def __init__(
        self,
        *,
        media_sha256: str,
        installation_media_paths: set[str] | frozenset[str],
        disk_inventory: Callable[[], list[dict[str, object]]] | None = None,
    ) -> None:
        if not self._HEX64.fullmatch(media_sha256):
            raise AdapterError("environment_untrusted", "physical media digest is invalid")
        paths = frozenset(installation_media_paths)
        if not paths or any(
            not isinstance(path, str) or not path.startswith("/dev/") for path in paths
        ):
            raise AdapterError(
                "environment_untrusted", "physical installation-media identity is invalid"
            )
        self.media_sha256 = media_sha256
        self.installation_media_paths = paths
        self.disk_inventory = disk_inventory or discover_guest_install_disks

    def verify(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1:
        target.validate()
        inventory = self.disk_inventory()
        if not isinstance(inventory, list) or any(not isinstance(item, dict) for item in inventory):
            raise AdapterError("environment_inventory_failed", "physical disk inventory is invalid")
        by_path = {item.get("path"): item for item in inventory}
        if not self.installation_media_paths.issubset(by_path):
            raise AdapterError(
                "environment_installation_media_changed",
                "physical installation media is missing or changed",
            )
        if target.path in self.installation_media_paths:
            raise AdapterError(
                "environment_target_protected", "installation media cannot be an install target"
            )
        current = by_path.get(target.path)
        if current is None:
            raise AdapterError("environment_target_mismatch", "physical target is missing")
        if current.get("read_only") is not False:
            raise AdapterError("environment_target_read_only", "physical target is read-only")
        if current.get("size_bytes") != target.size_bytes:
            raise AdapterError("environment_target_mismatch", "physical target capacity changed")
        serial = target.identity.get("serial")
        if serial is not None and current.get("serial") != serial:
            raise AdapterError("environment_target_mismatch", "physical target identity changed")
        planned = request.plan.get("plan", {}).get("target", {})
        if (
            planned.get("path") != target.path
            or planned.get("size_bytes") != target.size_bytes
            or planned.get("identity") != target.identity
            or planned.get("marker_sha256") != target.marker_sha256
        ):
            raise AdapterError("environment_target_mismatch", "plan target differs from hardware")
        inventory_sha256 = sha256_document(
            {
                "media_sha256": self.media_sha256,
                "installation_media_paths": sorted(self.installation_media_paths),
                "disk_inventory": sorted(inventory, key=lambda item: str(item.get("path"))),
            }
        )
        ownership_sha256 = sha256_document(
            {
                "target_identity_sha256": target.identity_sha256,
                "installation_media_paths": sorted(self.installation_media_paths),
            }
        )
        evidence = EnvironmentEvidenceV1(
            "kitpro-physical-console-environment-verifier-v1",
            "kitpro-physical-console-v1",
            self.media_sha256,
            inventory_sha256,
            ownership_sha256,
        )
        evidence.validate()
        return evidence


def discover_guest_install_disks() -> list[dict[str, object]]:
    """Return whole install-capable disks; exclude optical, loop, and RAM devices."""
    completed = subprocess.run(
        ["lsblk", "-J", "-b", "-d", "-o", "PATH,TYPE,SIZE,SERIAL,RO"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise AdapterError("environment_inventory_failed", "guest disk inventory failed")
    try:
        devices = json.loads(completed.stdout).get("blockdevices", [])
    except (AttributeError, json.JSONDecodeError) as error:
        raise AdapterError(
            "environment_inventory_failed", "guest disk inventory is invalid"
        ) from error
    if not isinstance(devices, list):
        raise AdapterError("environment_inventory_failed", "guest disk inventory is invalid")
    return sorted(
        (
            {
                "path": str(item.get("path")),
                "size_bytes": int(item.get("size", -1)),
                "serial": item.get("serial") or None,
                "read_only": bool(item.get("ro")),
            }
            for item in devices
            if isinstance(item, dict) and item.get("type") == "disk"
        ),
        key=lambda item: str(item["path"]),
    )


class FixtureSecretBroker:
    """Test-only secret inventory that stores references, never secret values."""

    def __init__(self, references: set[tuple[str, str]]) -> None:
        self._references = set(references)

    def available(self, reference: RuntimeSecretReference) -> bool:
        reference.validate()
        return (reference.provider, reference.reference) in self._references


class AuthoritativeExecutionBackend:
    """Reuse current validators and stop before importing the live engine."""

    def __init__(
        self,
        *,
        environment: EnvironmentVerifier | None = None,
        secrets: SecretBroker | None = None,
    ) -> None:
        self.environment = environment or UnavailableEnvironmentVerifier()
        self.secrets = secrets or UnavailableSecretBroker()

    @staticmethod
    def _plan(request: ExecutionRequestV1) -> dict[str, object]:
        value = request.plan.get("plan")
        if not isinstance(value, dict):
            raise AdapterError("plan_invalid", "execution request lacks the backend plan")
        return value

    @staticmethod
    def _spec(request: ExecutionRequestV1) -> InstallSpec:
        try:
            spec = parse_spec(request.installation_spec)
        except kitpro_repo.PipelineError as error:
            raise AdapterError("specification_invalid", str(error)) from error
        if not hmac.compare_digest(spec.sha256(), request.installation_spec_sha256):
            raise AdapterError(
                "specification_changed",
                "installation specification digest differs from the parsed specification",
            )
        return spec

    def verify_source(self, request: ExecutionRequestV1) -> SourceEvidenceV1:
        try:
            plan = self._plan(request)
            evidence = validate_install_source(plan)
        except (OSError, ValueError, kitpro_repo.PipelineError) as error:
            raise AdapterError("source_verification_failed", str(error)) from error
        try:
            result = SourceEvidenceV1(**evidence)
            result.validate()
        except (TypeError, AdapterError) as error:
            raise AdapterError("source_verification_failed", str(error)) from error
        repository = plan.get("repository", {})
        rootfs = plan.get("rootfs", {})
        checks = (
            (result.generation_manifest_sha256, repository.get("generation_manifest_sha256")),
            (result.artifact_set_sha256, repository.get("artifact_set_sha256")),
            (result.rootfs_profile_sha256, rootfs.get("profile_sha256")),
        )
        if any(
            not isinstance(planned, str) or not hmac.compare_digest(actual, planned)
            for actual, planned in checks
        ):
            raise AdapterError("source_changed", "verified source identity differs from the plan")
        return result

    def verify_target(self, request: ExecutionRequestV1) -> TargetEvidenceV1:
        spec = self._spec(request)
        try:
            current = discover_disk(
                Path(spec.disk.device),
                spec.disk.target_type,
                spec.disk.minimum_capacity_bytes,
            )
            assert_disk_unchanged(self._plan(request)["target"], current)
        except (OSError, KeyError, ValueError, kitpro_repo.PipelineError) as error:
            raise AdapterError("target_changed", str(error)) from error
        document = current.to_dict()
        return TargetEvidenceV1(
            path=current.path,
            target_type=current.target_type,
            size_bytes=current.size_bytes,
            identity=dict(current.identity),
            marker_sha256=current.marker_sha256,
            evidence_sha256=sha256_document(document),
        )

    def verify_plan(self, request: ExecutionRequestV1) -> None:
        spec = self._spec(request)
        try:
            plan = self._plan(request)
            validate_plan(plan)
        except kitpro_repo.PipelineError as error:
            raise AdapterError("plan_invalid", str(error)) from error
        if not hmac.compare_digest(request.plan.get("result_sha256", ""), request.plan_sha256):
            raise AdapterError("plan_changed", "request plan digest differs from the plan document")
        try:
            current = build_planning_result(spec)
        except (OSError, ValueError, kitpro_repo.PipelineError) as error:
            raise AdapterError("plan_rebuild_failed", str(error)) from error
        if not hmac.compare_digest(
            sha256_document(current.to_dict()),
            sha256_document(request.plan),
        ):
            raise AdapterError("plan_changed", "authoritative plan changed during preflight")

    def verify_environment(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1:
        return self.environment.verify(request, target)

    def secret_available(self, reference: RuntimeSecretReference) -> bool:
        return self.secrets.available(reference)


def safety_inventory() -> dict[str, object]:
    """Machine-readable proof that this adapter has no execution method."""
    methods = {
        name
        for name in dir(AuthoritativeExecutionBackend)
        if callable(getattr(AuthoritativeExecutionBackend, name)) and not name.startswith("_")
    }
    return {
        "schema_version": 1,
        "public_methods": sorted(methods),
        "destructive_methods": sorted(
            methods & {"apply", "execute", "install", "partition", "format"}
        ),
        "imports_live_engine": False,
        "simulation_only": True,
    }
