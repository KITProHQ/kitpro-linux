"""Versioned execution contract and a simulation that cannot mutate a target."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

ADAPTER_VERSION = "0.5.1"
ADAPTER_API_VERSION = 1
REQUEST_SCHEMA_VERSION = 1
RESPONSE_SCHEMA_VERSION = 1
HEX64 = re.compile(r"[0-9a-f]{64}")
REDACTED = "[REDACTED]"
SECRET_KEYS = ("password", "private_key", "secret", "credential", "token")


class AdapterError(ValueError):
    """A fail-closed adapter rejection with a stable non-secret code."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class CommitmentError(AdapterError):
    """A structured failure at or after the fake commitment boundary."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        disk_may_be_modified: bool,
        destructive_execution_performed: bool = False,
        retryable: bool = False,
    ) -> None:
        super().__init__(code, message, retryable=retryable)
        self.disk_may_be_modified = disk_may_be_modified
        self.destructive_execution_performed = destructive_execution_performed


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, separators=(",", ": ")) + "\n").encode()


def sha256_document(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_digest(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise AdapterError("invalid_request", f"{field_name} must be a SHA-256 digest")


def _exact_keys(value: Mapping[str, Any], expected: set[str], field_name: str) -> None:
    if set(value) != expected:
        raise AdapterError("invalid_request", f"{field_name} fields do not match schema version 1")


def redact(value: Any) -> Any:
    """Remove secret-bearing values from structured diagnostics."""
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED
            if any(part in str(key).lower() for part in SECRET_KEYS)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if any(f"{part}=" in lowered or f"{part}:" in lowered for part in SECRET_KEYS):
            return REDACTED
    return value


@dataclass(frozen=True, slots=True)
class RuntimeSecretReference:
    provider: str
    reference: str = field(repr=False)

    def validate(self) -> None:
        if self.provider not in {"memfd", "systemd-credential", "test-memory"}:
            raise AdapterError("invalid_secret_channel", "runtime secret provider is unsupported")
        if not self.reference or any(
            part in self.reference.lower() for part in ("password=", "private key")
        ):
            raise AdapterError("invalid_secret_channel", "runtime secret reference is invalid")

    def diagnostic(self) -> dict[str, str]:
        return {"provider": self.provider, "reference": REDACTED}


@dataclass(frozen=True, slots=True)
class SourceEvidenceV1:
    verifier: str
    generation: str
    generation_manifest_sha256: str
    artifact_set_sha256: str
    rootfs_profile_sha256: str
    evidence_sha256: str

    def validate(self) -> None:
        if self.verifier != "kitpro-production-verifier-v1":
            raise AdapterError(
                "source_untrusted", "source evidence is not from the production verifier"
            )
        for name in (
            "generation_manifest_sha256",
            "artifact_set_sha256",
            "rootfs_profile_sha256",
            "evidence_sha256",
        ):
            _require_digest(getattr(self, name), f"source.{name}")


@dataclass(frozen=True, slots=True)
class TargetEvidenceV1:
    path: str
    target_type: str
    size_bytes: int
    identity: dict[str, Any]
    marker_sha256: str | None
    evidence_sha256: str

    def validate(self) -> None:
        if not self.path.startswith("/") or self.target_type not in {"block", "image"}:
            raise AdapterError("target_invalid", "fresh target evidence is invalid")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes <= 0
        ):
            raise AdapterError("target_invalid", "fresh target capacity is invalid")
        _require_digest(self.evidence_sha256, "target.evidence_sha256")
        if self.marker_sha256 is not None:
            _require_digest(self.marker_sha256, "target.marker_sha256")

    @property
    def identity_sha256(self) -> str:
        return sha256_document(
            {
                "path": self.path,
                "target_type": self.target_type,
                "size_bytes": self.size_bytes,
                "identity": self.identity,
                "marker_sha256": self.marker_sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class EnvironmentEvidenceV1:
    verifier: str
    profile: str
    boot_artifact_sha256: str
    vm_identity_sha256: str
    target_ownership_sha256: str

    def validate(self) -> None:
        qemu_profiles = {
            "kitpro-phase3b2b-qemu-v1",
            "kitpro-phase3b2c-qemu-v1",
            "kitpro-phase3b2d-qemu-v1",
            "kitpro-phase3b2e-qemu-v1",
        }
        if self.verifier == "kitpro-qemu-environment-verifier-v1":
            profile_valid = self.profile in qemu_profiles
        elif self.verifier == "kitpro-physical-console-environment-verifier-v1":
            profile_valid = self.profile == "kitpro-physical-console-v1"
        else:
            raise AdapterError(
                "environment_untrusted", "execution environment verifier is unsupported"
            )
        if not profile_valid:
            raise AdapterError("environment_untrusted", "execution environment is not approved")
        for name in ("boot_artifact_sha256", "vm_identity_sha256", "target_ownership_sha256"):
            _require_digest(getattr(self, name), f"environment.{name}")


@dataclass(frozen=True, slots=True)
class ExecutionRequestV1:
    schema_version: int
    adapter_api_version: int
    installation_spec: dict[str, Any]
    installation_spec_sha256: str
    plan: dict[str, Any]
    plan_sha256: str
    installer_version: str
    planner_version: str
    planner_api_version: int
    contract_schema_version: int
    runtime_secret_required: bool

    @classmethod
    def create(
        cls,
        *,
        installation_spec: dict[str, Any],
        installation_spec_sha256: str,
        plan: dict[str, Any],
        plan_sha256: str,
        installer_version: str,
        planner_version: str,
        planner_api_version: int,
        contract_schema_version: int,
        runtime_secret_required: bool,
    ) -> ExecutionRequestV1:
        request = cls(
            REQUEST_SCHEMA_VERSION,
            ADAPTER_API_VERSION,
            installation_spec,
            installation_spec_sha256,
            plan,
            plan_sha256,
            installer_version,
            planner_version,
            planner_api_version,
            contract_schema_version,
            runtime_secret_required,
        )
        request.validate()
        return request

    @classmethod
    def from_dict(cls, value: Any) -> ExecutionRequestV1:
        if not isinstance(value, dict):
            raise AdapterError("invalid_request", "execution request must be an object")
        expected = {
            "schema_version",
            "adapter_api_version",
            "installation_spec",
            "installation_spec_sha256",
            "plan",
            "plan_sha256",
            "installer_version",
            "planner_version",
            "planner_api_version",
            "contract_schema_version",
            "runtime_secret_required",
        }
        _exact_keys(value, expected, "execution request")
        request = cls(**value)
        request.validate()
        return request

    def validate(self) -> None:
        if self.schema_version != REQUEST_SCHEMA_VERSION:
            raise AdapterError("unsupported_schema", "unsupported execution request schema")
        if self.adapter_api_version != ADAPTER_API_VERSION:
            raise AdapterError("unsupported_api", "unsupported execution adapter API")
        if not isinstance(self.installation_spec, dict) or not isinstance(self.plan, dict):
            raise AdapterError("invalid_request", "specification and plan must be objects")
        _require_digest(self.installation_spec_sha256, "installation_spec_sha256")
        _require_digest(self.plan_sha256, "plan_sha256")
        if not all(
            isinstance(value, str) and value
            for value in (self.installer_version, self.planner_version)
        ):
            raise AdapterError("invalid_request", "runtime versions must be non-empty strings")
        if self.planner_api_version != 1 or self.contract_schema_version != 1:
            raise AdapterError(
                "unsupported_version", "planner API or contract schema is unsupported"
            )
        if not isinstance(self.runtime_secret_required, bool):
            raise AdapterError("invalid_request", "runtime_secret_required must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizationBindingV1:
    request_sha256: str
    installation_spec_sha256: str
    plan_sha256: str
    source_evidence_sha256: str
    target_identity_sha256: str
    environment_identity_sha256: str
    installer_version: str
    planner_version: str
    planner_api_version: int
    adapter_version: str = ADAPTER_VERSION
    adapter_api_version: int = ADAPTER_API_VERSION
    contract_schema_version: int = 1

    def validate(self) -> None:
        for name in (
            "request_sha256",
            "installation_spec_sha256",
            "plan_sha256",
            "source_evidence_sha256",
            "target_identity_sha256",
            "environment_identity_sha256",
        ):
            _require_digest(getattr(self, name), name)
        if self.planner_api_version != 1:
            raise AdapterError(
                "unsupported_version", "authorization binds an unsupported planner API"
            )
        if (
            self.adapter_version != ADAPTER_VERSION
            or self.adapter_api_version != ADAPTER_API_VERSION
            or self.contract_schema_version != 1
        ):
            raise AdapterError(
                "unsupported_version", "authorization binds an unsupported adapter or contract"
            )

    @property
    def binding_sha256(self) -> str:
        self.validate()
        return sha256_document(asdict(self))


@dataclass(frozen=True, slots=True)
class PreflightEvidenceV1:
    """The exact independently produced evidence consumed by commitment."""

    binding: AuthorizationBindingV1
    source: SourceEvidenceV1
    target: TargetEvidenceV1
    environment: EnvironmentEvidenceV1

    def validate(self) -> None:
        self.binding.validate()
        self.source.validate()
        self.target.validate()
        self.environment.validate()


@dataclass(frozen=True, slots=True)
class CommitmentResultV1:
    """Credential-free result returned by a narrowly scoped commitment boundary."""

    status: str
    report_path: str | None
    report_sha256: str | None
    disk_may_be_modified: bool
    destructive_execution_performed: bool

    def validate(self) -> None:
        if self.status not in {"simulated", "completed"}:
            raise AdapterError("commitment_result_invalid", "commitment status is unsupported")
        if self.report_sha256 is not None:
            _require_digest(self.report_sha256, "commitment.report_sha256")
        if self.status == "simulated" and (
            self.disk_may_be_modified or self.destructive_execution_performed
        ):
            raise AdapterError(
                "commitment_result_invalid",
                "simulated commitment cannot report destructive execution",
            )


@dataclass(slots=True)
class _AuthorizationRecord:
    binding_sha256: str
    expires_at: float
    consumed: bool = False


class OneTimeAuthorizationAuthority:
    """Privileged in-memory authorization records for simulation qualification only."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
        test_issuance_enabled: bool = False,
    ) -> None:
        self._clock = clock
        self._token_factory = token_factory
        self._test_issuance_enabled = test_issuance_enabled
        self._records: dict[str, _AuthorizationRecord] = {}

    @classmethod
    def for_tests(
        cls,
        *,
        clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ) -> OneTimeAuthorizationAuthority:
        return cls(clock=clock, token_factory=token_factory, test_issuance_enabled=True)

    def issue_test_only(self, binding: AuthorizationBindingV1, ttl_seconds: float) -> str:
        if not self._test_issuance_enabled:
            raise AdapterError("authorization_unavailable", "authorization issuance is disabled")
        if ttl_seconds <= 0 or ttl_seconds > 300:
            raise AdapterError("authorization_invalid", "authorization lifetime is out of bounds")
        identifier = self._token_factory()
        if not identifier or identifier in self._records:
            raise AdapterError("authorization_invalid", "authorization identifier is invalid")
        self._records[identifier] = _AuthorizationRecord(
            binding.binding_sha256,
            self._clock() + ttl_seconds,
        )
        return identifier

    def consume(self, identifier: str | None, binding: AuthorizationBindingV1) -> str:
        if not identifier:
            raise AdapterError("authorization_missing", "one-time authorization is required")
        record = self._records.get(identifier)
        if record is None:
            raise AdapterError("authorization_invalid", "one-time authorization is unknown")
        if record.consumed:
            raise AdapterError(
                "authorization_replayed", "one-time authorization was already consumed"
            )
        record.consumed = True
        if self._clock() > record.expires_at:
            raise AdapterError("authorization_expired", "one-time authorization expired")
        if not hmac.compare_digest(record.binding_sha256, binding.binding_sha256):
            raise AdapterError("authorization_mismatch", "one-time authorization binding changed")
        return hashlib.sha256(identifier.encode()).hexdigest()


class ExecutionBackendPort(Protocol):
    def verify_source(self, request: ExecutionRequestV1) -> SourceEvidenceV1: ...

    def verify_target(self, request: ExecutionRequestV1) -> TargetEvidenceV1: ...

    def verify_plan(self, request: ExecutionRequestV1) -> None: ...

    def verify_environment(
        self, request: ExecutionRequestV1, target: TargetEvidenceV1
    ) -> EnvironmentEvidenceV1: ...

    def secret_available(self, reference: RuntimeSecretReference) -> bool: ...


@dataclass(frozen=True, slots=True)
class ExecutionEventV1:
    sequence: int
    stage: str
    status: str
    message: str


@dataclass(frozen=True, slots=True)
class ExecutionResponseV1:
    schema_version: int
    adapter_api_version: int
    status: str
    request_sha256: str
    authorization_sha256: str | None
    events: tuple[ExecutionEventV1, ...]
    error_code: str | None
    error_message: str | None
    disk_may_be_modified: bool
    destructive_execution_performed: bool

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["events"] = [asdict(event) for event in self.events]
        return value


@dataclass(slots=True)
class CancellationToken:
    cancelled: bool = False

    def cancel(self) -> None:
        self.cancelled = True


class ExecutionSimulator:
    """Run preflight and authorization, then stop before destructive commitment."""

    def __init__(
        self,
        backend: ExecutionBackendPort,
        authority: OneTimeAuthorizationAuthority,
    ) -> None:
        self.backend = backend
        self.authority = authority
        self._attempts: set[str] = set()

    def preflight_binding(
        self,
        request: ExecutionRequestV1,
        *,
        secret: RuntimeSecretReference | None,
        emit: Callable[[ExecutionEventV1], None] | None = None,
        cancel: CancellationToken | None = None,
    ) -> tuple[AuthorizationBindingV1, tuple[ExecutionEventV1, ...]]:
        evidence, events = self.preflight_evidence(
            request,
            secret=secret,
            emit=emit,
            cancel=cancel,
        )
        return evidence.binding, events

    def preflight_evidence(
        self,
        request: ExecutionRequestV1,
        *,
        secret: RuntimeSecretReference | None,
        require_runtime_secret: bool = True,
        emit: Callable[[ExecutionEventV1], None] | None = None,
        cancel: CancellationToken | None = None,
    ) -> tuple[PreflightEvidenceV1, tuple[ExecutionEventV1, ...]]:
        request.validate()
        events: list[ExecutionEventV1] = []

        def event(stage: str, message: str) -> None:
            item = ExecutionEventV1(len(events) + 1, stage, "passed", message)
            if emit is not None:
                emit(item)
            events.append(item)
            if cancel is not None and cancel.cancelled:
                raise AdapterError("cancelled", "execution simulation was cancelled")

        event("request", "Execution request schema and versions are supported")
        source = self.backend.verify_source(request)
        source.validate()
        event("source", "Production source evidence is valid")
        target = self.backend.verify_target(request)
        target.validate()
        event("target", "Fresh target identity matches the selected target")
        self.backend.verify_plan(request)
        event("plan", "Authoritative plan matches the current inputs")
        environment = self.backend.verify_environment(request, target)
        environment.validate()
        event("environment", "Disposable QEMU execution environment is recognized")
        if request.runtime_secret_required and require_runtime_secret:
            if secret is None:
                raise AdapterError("secret_missing", "required runtime secret is missing")
            secret.validate()
            if not self.backend.secret_available(secret):
                raise AdapterError("secret_missing", "required runtime secret is unavailable")
            event("secret", "Required runtime secret is available through an ephemeral channel")
        planned_target = request.plan.get("plan", {}).get("target", {})
        target_digest = sha256_document(
            {
                "path": planned_target.get("path"),
                "target_type": planned_target.get("target_type"),
                "size_bytes": planned_target.get("size_bytes"),
                "identity": planned_target.get("identity"),
                "marker_sha256": planned_target.get("marker_sha256"),
            }
        )
        if not hmac.compare_digest(target.identity_sha256, target_digest):
            raise AdapterError("target_changed", "fresh target identity differs from the plan")
        source_digest = sha256_document(asdict(source))
        environment_digest = sha256_document(asdict(environment))
        binding = AuthorizationBindingV1(
            request.request_sha256,
            request.installation_spec_sha256,
            request.plan_sha256,
            source_digest,
            target.identity_sha256,
            environment_digest,
            request.installer_version,
            request.planner_version,
            request.planner_api_version,
            ADAPTER_VERSION,
            request.adapter_api_version,
            request.contract_schema_version,
        )
        binding.validate()
        evidence = PreflightEvidenceV1(binding, source, target, environment)
        evidence.validate()
        return evidence, tuple(events)

    def simulate(
        self,
        request: ExecutionRequestV1,
        *,
        authorization_id: str | None,
        secret: RuntimeSecretReference | None = None,
        emit: Callable[[ExecutionEventV1], None] | None = None,
        cancel: CancellationToken | None = None,
        fail_storage_preview: bool = False,
    ) -> ExecutionResponseV1:
        events: tuple[ExecutionEventV1, ...] = ()
        authorization_sha256: str | None = None
        try:
            if request.request_sha256 in self._attempts:
                raise AdapterError("request_repeated", "execution request was already submitted")
            binding, events = self.preflight_binding(
                request,
                secret=secret,
                emit=emit,
                cancel=cancel,
            )
            if cancel is not None and cancel.cancelled:
                raise AdapterError("cancelled", "execution simulation was cancelled")
            authorization_sha256 = self.authority.consume(authorization_id, binding)
            authorization_event = ExecutionEventV1(
                len(events) + 1,
                "authorization",
                "passed",
                "One-time authorization matches the exact preflight binding",
            )
            if emit is not None:
                emit(authorization_event)
            events = (*events, authorization_event)
            self._attempts.add(request.request_sha256)
            if fail_storage_preview:
                raise AdapterError(
                    "storage_preview_failed",
                    "simulated storage operation failed before destructive commitment",
                    retryable=True,
                )
            blocked = ExecutionEventV1(
                len(events) + 1,
                "commitment",
                "blocked",
                "Live installation is unavailable; no destructive operation was called",
            )
            if emit is not None:
                emit(blocked)
            events = (*events, blocked)
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "simulated",
                request.request_sha256,
                authorization_sha256,
                events,
                None,
                None,
                False,
                False,
            )
        except AdapterError as error:
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "cancelled" if error.code == "cancelled" else "denied",
                request.request_sha256,
                authorization_sha256,
                events,
                error.code,
                str(redact(str(error))),
                False,
                False,
            )
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "failed",
                request.request_sha256,
                authorization_sha256,
                events,
                "adapter_failure",
                str(redact(str(error))),
                False,
                False,
            )
