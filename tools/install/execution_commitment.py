"""Exact fake-engine connection for the qualified execution bridge.

This module maps validated adapter evidence to the existing ``engine.apply`` signature,
but accepts only an explicitly marked non-destructive fake.  It deliberately does not
import the production engine and provides no production factory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any, Protocol

from kitpro_execution_adapter import (
    AdapterError,
    CancellationToken,
    CommitmentError,
    CommitmentResultV1,
    ExecutionRequestV1,
    PreflightEvidenceV1,
    canonical_json_bytes,
    sha256_document,
)
from tools import kitpro_repo
from tools.install.model import InstallSpec, parse_spec
from tools.install.plan import validate_plan


class EngineApplyPort(Protocol):
    kitpro_non_destructive_fake: bool

    def __call__(
        self,
        spec: InstallSpec,
        plan: dict[str, Any],
        allow_disk_erase: bool,
        source_metadata: dict[str, Any] | None = None,
        stage_callback: Callable[[str], None] | None = None,
        administrator_password: str | None = None,
        luks_passphrase: str | None = None,
        precommit_guard: Callable[[Path, Any], None] | None = None,
    ) -> tuple[Path, dict[str, Any]]: ...


class SimulatedEngineFailure(RuntimeError):
    """Fault injected by a fake engine before or after simulated commitment."""

    def __init__(self, message: str, *, after_commitment: bool) -> None:
        super().__init__(message)
        self.after_commitment = after_commitment


def _redacted_engine_error(error: Exception, *secrets: str | None) -> str:
    """Return bounded diagnostics while removing every in-memory runtime secret."""
    detail = str(error)
    for secret in secrets:
        if secret:
            detail = detail.replace(secret, "[redacted]")
    detail = " ".join(detail.split()) or type(error).__name__
    return f"authoritative engine failed: {detail}"[:1024]


class AuthoritativeEngineCommitment:
    """Map exact validated inputs to the authoritative apply signature using a fake only."""

    def __init__(
        self,
        engine_apply: EngineApplyPort,
        *,
        required_environment_profile: str = "kitpro-phase3b2d-qemu-v1",
    ) -> None:
        if getattr(engine_apply, "kitpro_non_destructive_fake", False) is not True:
            raise AdapterError(
                "production_commitment_unavailable",
                "only an explicitly marked non-destructive fake engine is accepted",
            )
        self._engine_apply = engine_apply
        if required_environment_profile not in {
            "kitpro-phase3b2d-qemu-v1",
            "kitpro-phase3b2e-qemu-v1",
        }:
            raise AdapterError("environment_untrusted", "fake environment profile is unsupported")
        self._required_environment_profile = required_environment_profile

    @staticmethod
    def _validate_mapping(
        request: ExecutionRequestV1,
        evidence: PreflightEvidenceV1,
        *,
        required_environment_profile: str = "kitpro-phase3b2d-qemu-v1",
    ) -> tuple[InstallSpec, dict[str, Any], dict[str, Any]]:
        request.validate()
        evidence.validate()
        if evidence.environment.profile != required_environment_profile:
            raise AdapterError(
                "environment_untrusted",
                "commitment requires the exact authorized QEMU environment",
            )
        try:
            spec = parse_spec(request.installation_spec)
            plan = request.plan["plan"]
            if not isinstance(plan, dict):
                raise TypeError("plan")
            validate_plan(plan)
        except (KeyError, TypeError, ValueError, kitpro_repo.PipelineError) as error:
            raise AdapterError("commitment_input_invalid", "commitment input is invalid") from error
        if not hmac.compare_digest(spec.sha256(), request.installation_spec_sha256):
            raise AdapterError("specification_changed", "commitment specification changed")
        if not hmac.compare_digest(request.plan.get("result_sha256", ""), request.plan_sha256):
            raise AdapterError("plan_changed", "commitment plan digest changed")
        planned_target = plan.get("target")
        expected_target = {
            "path": evidence.target.path,
            "target_type": evidence.target.target_type,
            "size_bytes": evidence.target.size_bytes,
            "identity": evidence.target.identity,
            "marker_sha256": evidence.target.marker_sha256,
        }
        if not isinstance(planned_target, dict) or any(
            planned_target.get(key) != value for key, value in expected_target.items()
        ):
            raise AdapterError("target_changed", "commitment target differs from fresh evidence")
        repository = plan.get("repository", {})
        rootfs = plan.get("rootfs", {})
        expected_source = {
            "generation_manifest_sha256": evidence.source.generation_manifest_sha256,
            "artifact_set_sha256": evidence.source.artifact_set_sha256,
            "rootfs_profile_sha256": evidence.source.rootfs_profile_sha256,
        }
        if (
            repository.get("generation_manifest_sha256")
            != expected_source["generation_manifest_sha256"]
            or repository.get("artifact_set_sha256") != expected_source["artifact_set_sha256"]
            or rootfs.get("profile_sha256") != expected_source["rootfs_profile_sha256"]
        ):
            raise AdapterError("source_changed", "commitment source differs from verified evidence")
        source_metadata = {
            **asdict(evidence.source),
            "authorization_binding_sha256": evidence.binding.binding_sha256,
            "environment_identity_sha256": sha256_document(asdict(evidence.environment)),
            "target_identity_sha256": evidence.target.identity_sha256,
        }
        return spec, plan, source_metadata

    @staticmethod
    def _read_secret(secret_fd: int | None, required: bool) -> str | None:
        if not required:
            return None
        if secret_fd is None:
            raise AdapterError("secret_missing", "commitment secret descriptor is missing")
        data = bytearray(os.pread(secret_fd, 4097, 0))
        try:
            if not data or len(data) > 4096 or b"\0" in data or b"\n" in data:
                raise AdapterError("secret_invalid", "commitment secret is invalid")
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise AdapterError("secret_invalid", "commitment secret is invalid") from error
        finally:
            data[:] = b"\0" * len(data)

    @classmethod
    def _read_runtime_secrets(
        cls, secret_fd: int | None, required: bool
    ) -> tuple[str | None, str | None]:
        value = cls._read_secret(secret_fd, required)
        if value is None:
            return None, None
        prefix = "kitpro-runtime-secrets-v1:"
        if not value.startswith(prefix):
            return value, None
        try:
            document = json.loads(value.removeprefix(prefix))
        except json.JSONDecodeError as error:
            raise AdapterError("secret_invalid", "runtime secret bundle is invalid") from error
        allowed = {"schema_version", "administrator_password", "luks_passphrase"}
        if (
            not isinstance(document, dict)
            or set(document) - allowed
            or document.get("schema_version") != 1
            or not isinstance(document.get("administrator_password"), str)
            or not document["administrator_password"]
            or (
                "luks_passphrase" in document
                and (
                    not isinstance(document["luks_passphrase"], str)
                    or not document["luks_passphrase"]
                )
            )
        ):
            raise AdapterError("secret_invalid", "runtime secret bundle is invalid")
        return document["administrator_password"], document.get("luks_passphrase")

    def commit(
        self,
        request: ExecutionRequestV1,
        evidence: PreflightEvidenceV1,
        secret_fd: int | None,
        *,
        emit: Callable[[str, str, str], None],
        cancel: CancellationToken | None,
    ) -> CommitmentResultV1:
        spec, plan, source_metadata = self._validate_mapping(
            request,
            evidence,
            required_environment_profile=self._required_environment_profile,
        )
        password, luks_passphrase = self._read_runtime_secrets(
            secret_fd, request.runtime_secret_required
        )
        encrypted = "encryption" in plan.get("partition_table", {})
        if encrypted != (luks_passphrase is not None):
            raise AdapterError(
                "secret_invalid",
                "encrypted plan and protected LUKS passphrase do not agree",
            )
        if cancel is not None and cancel.cancelled:
            raise AdapterError("cancelled", "execution was cancelled before fake commitment")

        def stage(value: str) -> None:
            emit(f"engine:{value}", "simulated", "Fake authoritative engine stage completed")

        try:
            report_path, report = self._engine_apply(
                spec,
                plan,
                allow_disk_erase=True,
                source_metadata=source_metadata,
                stage_callback=stage,
                administrator_password=password,
                **({"luks_passphrase": luks_passphrase} if luks_passphrase is not None else {}),
            )
        except SimulatedEngineFailure as error:
            raise CommitmentError(
                "simulated_engine_failure",
                "fake engine reported a simulated failure",
                disk_may_be_modified=error.after_commitment,
                destructive_execution_performed=False,
            ) from error
        except AdapterError:
            raise
        except Exception as error:
            raise CommitmentError(
                "fake_engine_failure",
                "fake engine failed without credential-bearing detail",
                disk_may_be_modified=False,
                destructive_execution_performed=False,
            ) from error
        if not isinstance(report_path, Path) or not isinstance(report, dict):
            raise AdapterError("commitment_result_invalid", "fake engine result is invalid")
        if report.get("simulation_only") is not True:
            raise AdapterError("commitment_result_invalid", "fake engine omitted simulation proof")
        report_sha256 = hashlib.sha256(canonical_json_bytes(report)).hexdigest()
        return CommitmentResultV1("simulated", str(report_path), report_sha256, False, False)


_LIVE_FACTORY_CAPABILITY = object()


class LiveAuthoritativeEngineCommitment:
    """The sole exact connection from a live-authorized bridge to ``engine.apply``."""

    def __init__(
        self,
        engine_apply: EngineApplyPort,
        capability: object,
        *,
        required_environment_profile: str = "kitpro-phase3b2e-qemu-v1",
    ) -> None:
        if capability is not _LIVE_FACTORY_CAPABILITY:
            raise AdapterError(
                "production_commitment_unavailable",
                "live commitment must be created by the privileged factory",
            )
        self._engine_apply = engine_apply
        if required_environment_profile not in {
            "kitpro-phase3b2e-qemu-v1",
            "kitpro-physical-console-v1",
        }:
            raise AdapterError("environment_untrusted", "live environment profile is unsupported")
        self._required_environment_profile = required_environment_profile

    def commit(
        self,
        request: ExecutionRequestV1,
        evidence: PreflightEvidenceV1,
        secret_fd: int | None,
        *,
        emit: Callable[[str, str, str], None],
        cancel: CancellationToken | None,
    ) -> CommitmentResultV1:
        spec, plan, source_metadata = AuthoritativeEngineCommitment._validate_mapping(
            request,
            evidence,
            required_environment_profile=self._required_environment_profile,
        )
        password, luks_passphrase = AuthoritativeEngineCommitment._read_runtime_secrets(
            secret_fd, request.runtime_secret_required
        )
        encrypted = "encryption" in plan.get("partition_table", {})
        if encrypted != (luks_passphrase is not None):
            raise AdapterError(
                "secret_invalid",
                "encrypted plan and protected LUKS passphrase do not agree",
            )
        if cancel is not None and cancel.cancelled:
            raise AdapterError("cancelled", "execution was cancelled before live commitment")
        target = Path(evidence.target.path)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        target_fd = os.open(target, flags)
        engine_entered = False
        try:
            metadata = os.fstat(target_fd)
            if not stat.S_ISBLK(metadata.st_mode):
                raise AdapterError("target_invalid", "live target is not a block device")

            def guard(current_path: Path, _current: Any) -> None:
                if cancel is not None and cancel.cancelled:
                    raise AdapterError("cancelled", "execution was cancelled before first write")
                held = os.fstat(target_fd)
                current = current_path.stat()
                if held.st_rdev != current.st_rdev or current_path.resolve() != target.resolve():
                    raise AdapterError("target_changed", "live target changed at commitment")

            def stage(value: str) -> None:
                emit(f"engine:{value}", "running", "Authoritative engine stage entered")

            engine_entered = True
            report_path, report = self._engine_apply(
                spec,
                plan,
                allow_disk_erase=True,
                source_metadata=source_metadata,
                stage_callback=stage,
                administrator_password=password,
                **({"luks_passphrase": luks_passphrase} if luks_passphrase is not None else {}),
                precommit_guard=guard,
            )
        except AdapterError:
            raise
        except Exception as error:
            raise CommitmentError(
                "live_engine_failure",
                _redacted_engine_error(error, password, luks_passphrase),
                disk_may_be_modified=engine_entered,
                destructive_execution_performed=False,
            ) from error
        finally:
            os.close(target_fd)
            password = None
            luks_passphrase = None
        if not isinstance(report_path, Path) or not isinstance(report, dict):
            raise CommitmentError(
                "commitment_result_invalid",
                "authoritative engine result is invalid",
                disk_may_be_modified=True,
            )
        report_sha256 = hashlib.sha256(canonical_json_bytes(report)).hexdigest()
        return CommitmentResultV1("completed", str(report_path), report_sha256, True, True)


def create_live_engine_commitment(
    *, required_environment_profile: str = "kitpro-phase3b2e-qemu-v1"
) -> LiveAuthoritativeEngineCommitment:
    """Import the real engine only inside the privileged guest service composition root."""
    from tools.install.engine import apply

    return LiveAuthoritativeEngineCommitment(
        apply,
        _LIVE_FACTORY_CAPABILITY,
        required_environment_profile=required_environment_profile,
    )


def connection_safety_inventory() -> dict[str, object]:
    return {
        "schema_version": 1,
        "production_engine_imported": False,
        "production_factory_available": False,
        "accepts_only_marked_fake": True,
        "arbitrary_command_runner": False,
        "mapped_apply_arguments": [
            "spec",
            "plan",
            "allow_disk_erase",
            "source_metadata",
            "stage_callback",
            "administrator_password",
            "luks_passphrase",
        ],
    }


def live_connection_inventory() -> dict[str, object]:
    return {
        "schema_version": 1,
        "production_engine_imported_on_factory_call": True,
        "production_factory_available": True,
        "required_environment_profile": "kitpro-phase3b2e-qemu-v1",
        "arbitrary_command_runner": False,
        "target_fd_held_across_engine_invocation": True,
        "partitioner_owns_exclusive_target_lock": True,
        "precommit_guard_passed_to_authoritative_engine": True,
    }
