"""Narrow non-destructive bridge that stops at the irreversible boundary."""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from .api import (
    ADAPTER_API_VERSION,
    RESPONSE_SCHEMA_VERSION,
    AdapterError,
    CancellationToken,
    CommitmentError,
    CommitmentResultV1,
    ExecutionBackendPort,
    ExecutionEventV1,
    ExecutionRequestV1,
    ExecutionResponseV1,
    ExecutionSimulator,
    PreflightEvidenceV1,
    RuntimeSecretReference,
    canonical_json_bytes,
    redact,
)
from .secret_broker import ProtectedSecretBroker
from .security import (
    ExecutionRevocationStore,
    LiveAuthorizationVerifier,
    QualificationAuthorizationVerifier,
    SignedAuthorizationV1,
)


class CommitmentBoundary(Protocol):
    def commit(
        self,
        request: ExecutionRequestV1,
        evidence: PreflightEvidenceV1,
        secret_fd: int | None,
        *,
        emit: Callable[[str, str, str], None],
        cancel: CancellationToken | None,
    ) -> CommitmentResultV1: ...


class _NoRevocations:
    def assert_not_revoked(self, request_sha256: str) -> None:
        del request_sha256


class DisabledCommitmentBoundary:
    """A structural stop: no production executor is accepted or imported."""

    def commit(
        self,
        request: ExecutionRequestV1,
        evidence: PreflightEvidenceV1,
        secret_fd: int | None,
        *,
        emit: Callable[[str, str, str], None],
        cancel: CancellationToken | None,
    ) -> CommitmentResultV1:
        del request, evidence, secret_fd, emit, cancel
        raise AdapterError(
            "commitment_disabled",
            "destructive commitment is unavailable in the Phase 3B.2D build",
        )


class CommitmentAuditStore:
    """Record the reached boundary without secret or bearer authorization material."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise AdapterError("audit_store_invalid", "commitment audit store is not private")

    def record(
        self,
        *,
        request_sha256: str,
        authorization_sha256: str,
        binding_sha256: str,
    ) -> Path:
        path = self.root / request_sha256
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError as error:
            raise AdapterError(
                "request_repeated", "execution request was already committed"
            ) from error
        try:
            os.write(
                fd,
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "status": "commitment_intent_persisted",
                        "request_sha256": request_sha256,
                        "authorization_sha256": authorization_sha256,
                        "binding_sha256": binding_sha256,
                        "recorded_at": int(time.time()),
                        "disk_may_be_modified": False,
                    }
                ),
            )
            os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return path


class NonDestructivePrivilegedBridge:
    """Revalidate every binding, consume authority and secret, then refuse commitment."""

    def __init__(
        self,
        *,
        backend: ExecutionBackendPort,
        authorization: QualificationAuthorizationVerifier,
        secrets: ProtectedSecretBroker,
        audit: CommitmentAuditStore,
        commitment: CommitmentBoundary | None = None,
        revocations: ExecutionRevocationStore | None = None,
    ) -> None:
        self.backend = backend
        self.authorization = authorization
        self.secrets = secrets
        self.audit = audit
        self.commitment = commitment or DisabledCommitmentBoundary()
        self.revocations = revocations or _NoRevocations()

    def authorization_evidence(
        self,
        request: ExecutionRequestV1,
        *,
        cancel: CancellationToken | None = None,
    ) -> tuple[PreflightEvidenceV1, tuple[ExecutionEventV1, ...]]:
        """Produce verifier-owned evidence before authorization or secret delivery."""
        self.revocations.assert_not_revoked(request.request_sha256)
        simulator = ExecutionSimulator(self.backend, authority=None)  # type: ignore[arg-type]
        return simulator.preflight_evidence(
            request,
            secret=None,
            require_runtime_secret=False,
            cancel=cancel,
        )

    def prepare(
        self,
        request: ExecutionRequestV1,
        *,
        authorization: SignedAuthorizationV1,
        secret: RuntimeSecretReference | None,
        emit: Callable[[ExecutionEventV1], None] | None = None,
        cancel: CancellationToken | None = None,
    ) -> ExecutionResponseV1:
        events: list[ExecutionEventV1] = []
        authorization_sha256: str | None = None

        def event(stage: str, status: str, message: str) -> None:
            item = ExecutionEventV1(len(events) + 1, stage, status, message)
            if emit is not None:
                emit(item)
            events.append(item)
            if cancel is not None and cancel.cancelled:
                raise AdapterError("cancelled", "execution was cancelled before commitment")

        try:
            self.revocations.assert_not_revoked(request.request_sha256)
            simulator = ExecutionSimulator(self.backend, authority=None)  # type: ignore[arg-type]
            evidence, first_events = simulator.preflight_evidence(
                request,
                secret=secret,
                emit=emit,
                cancel=cancel,
            )
            events.extend(first_events)
            binding = evidence.binding
            event("operator-approval", "passed", "Trusted operator approval is bound to preflight")
            authorization_sha256 = self.authorization.verify_and_consume(authorization, binding)
            event("authorization", "passed", "Signed single-use authorization is valid")

            # Re-run authoritative source, target, plan and environment checks after
            # consuming authorization and immediately before the disabled commitment.
            fresh_evidence, _ = simulator.preflight_evidence(request, secret=secret, cancel=cancel)
            if fresh_evidence.binding.binding_sha256 != binding.binding_sha256:
                raise AdapterError("precommit_changed", "pre-commit binding changed")
            event("precommit", "passed", "Immediate safety revalidation matches authorization")
            if request.runtime_secret_required:
                if secret is None:
                    raise AdapterError("secret_missing", "required runtime secret is missing")
                with self.secrets.acquire(
                    secret,
                    request_sha256=request.request_sha256,
                    authorization_sha256=authorization_sha256,
                ) as lease:
                    if os.fstat(lease.fd).st_size <= 0:
                        raise AdapterError("secret_unavailable", "runtime secret channel is empty")
                    event("secret", "passed", "Bound sealed secret descriptor is ready")
                    self.audit.record(
                        request_sha256=request.request_sha256,
                        authorization_sha256=authorization_sha256,
                        binding_sha256=binding.binding_sha256,
                    )
                    self.revocations.assert_not_revoked(request.request_sha256)
                    self.authorization.assert_current(authorization, binding)
                    if cancel is not None and cancel.cancelled:
                        raise AdapterError("cancelled", "execution was cancelled before commitment")
                    result = self.commitment.commit(
                        request,
                        fresh_evidence,
                        lease.fd,
                        emit=event,
                        cancel=cancel,
                    )
            else:
                self.audit.record(
                    request_sha256=request.request_sha256,
                    authorization_sha256=authorization_sha256,
                    binding_sha256=binding.binding_sha256,
                )
                self.revocations.assert_not_revoked(request.request_sha256)
                self.authorization.assert_current(authorization, binding)
                if cancel is not None and cancel.cancelled:
                    raise AdapterError("cancelled", "execution was cancelled before commitment")
                result = self.commitment.commit(
                    request,
                    fresh_evidence,
                    None,
                    emit=event,
                    cancel=cancel,
                )
            result.validate()
            event(
                "commitment",
                result.status,
                (
                    "Authoritative engine completed"
                    if result.status == "completed"
                    else "Fake engine completed without target mutation"
                ),
            )
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                result.status,
                request.request_sha256,
                authorization_sha256,
                tuple(events),
                None,
                None,
                result.disk_may_be_modified,
                result.destructive_execution_performed,
            )
        except CommitmentError as error:
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "failed",
                request.request_sha256,
                authorization_sha256,
                tuple(events),
                error.code,
                str(redact(str(error))),
                error.disk_may_be_modified,
                error.destructive_execution_performed,
            )
        except AdapterError as error:
            if error.code == "commitment_disabled":
                event(
                    "commitment",
                    "blocked",
                    "Live engine is disconnected; no disk-modifying operation was called",
                )
                return ExecutionResponseV1(
                    RESPONSE_SCHEMA_VERSION,
                    ADAPTER_API_VERSION,
                    "qualified",
                    request.request_sha256,
                    authorization_sha256,
                    tuple(events),
                    error.code,
                    str(error),
                    False,
                    False,
                )
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "cancelled" if error.code == "cancelled" else "denied",
                request.request_sha256,
                authorization_sha256,
                tuple(events),
                error.code,
                str(redact(str(error))),
                False,
                False,
            )
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            return ExecutionResponseV1(
                RESPONSE_SCHEMA_VERSION,
                ADAPTER_API_VERSION,
                "denied",
                request.request_sha256,
                authorization_sha256,
                tuple(events),
                "bridge_failure",
                str(redact(str(error))),
                False,
                False,
            )


class LivePrivilegedBridge(NonDestructivePrivilegedBridge):
    """Live-capable bridge requiring the distinct VM-live authorization verifier."""

    def __init__(
        self,
        *,
        backend: ExecutionBackendPort,
        authorization: LiveAuthorizationVerifier,
        secrets: ProtectedSecretBroker,
        audit: CommitmentAuditStore,
        commitment: CommitmentBoundary,
        revocations: ExecutionRevocationStore,
    ) -> None:
        if not isinstance(authorization, LiveAuthorizationVerifier):
            raise AdapterError(
                "authorization_scope_invalid",
                "live bridge requires the VM-live authorization verifier",
            )
        if isinstance(commitment, DisabledCommitmentBoundary):
            raise AdapterError("commitment_disabled", "live commitment is not configured")
        super().__init__(
            backend=backend,
            authorization=authorization,
            secrets=secrets,
            audit=audit,
            commitment=commitment,
            revocations=revocations,
        )


def bridge_safety_inventory() -> dict[str, object]:
    methods = {
        name
        for name in dir(NonDestructivePrivilegedBridge)
        if callable(getattr(NonDestructivePrivilegedBridge, name)) and not name.startswith("_")
    }
    return {
        "schema_version": 1,
        "public_methods": sorted(methods),
        "production_executor_connected": False,
        "imports_live_engine": False,
        "real_commitment_factory_available": False,
        "live_bridge_available": True,
        "destructive_methods": sorted(methods & {"apply", "execute", "install", "wipe"}),
        "response_fields": sorted(
            asdict(ExecutionResponseV1(1, 1, "", "", None, (), None, None, False, False))
        ),
    }
