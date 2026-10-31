"""Narrow privileged guest-service boundary for VM-scoped installation."""

from __future__ import annotations

import hmac
import json
import os
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from .api import (
    ADAPTER_API_VERSION,
    AdapterError,
    CancellationToken,
    ExecutionEventV1,
    ExecutionRequestV1,
    ExecutionResponseV1,
    RuntimeSecretReference,
)
from .bridge import LivePrivilegedBridge
from .secret_broker import ProtectedSecretBroker
from .security import LIVE_AUTHORIZATION_SCOPE, SignedAuthorizationV1, parse_signed_authorization

SERVICE_SCHEMA_VERSION = 1
HEX64 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Kernel-originated peer identity, not caller-supplied request data."""

    pid: int
    uid: int
    gid: int
    executable_sha256: str


class PrivilegedGuestService:
    """Authenticate one operator client and delegate only a versioned install request."""

    def __init__(
        self,
        *,
        bridge: LivePrivilegedBridge,
        secrets: ProtectedSecretBroker,
        expected_client_uid: int,
        expected_client_executable_sha256: str,
    ) -> None:
        if expected_client_uid < 0 or not HEX64.fullmatch(expected_client_executable_sha256):
            raise AdapterError("service_configuration_invalid", "service client pin is invalid")
        self.bridge = bridge
        self.secrets = secrets
        self.expected_client_uid = expected_client_uid
        self.expected_client_executable_sha256 = expected_client_executable_sha256
        self._active_request: str | None = None

    def authorization_request(
        self,
        peer: PeerCredentials,
        request_value: dict[str, Any],
        *,
        iso: dict[str, Any],
        target: dict[str, Any],
        vm_session_id: str,
        cancel: CancellationToken | None = None,
    ) -> dict[str, Any]:
        """Create the exact issuer packet from fresh privileged verification."""
        self.authenticate(peer)
        if not HEX64.fullmatch(vm_session_id):
            raise AdapterError("service_request_invalid", "VM session identity is invalid")
        request = ExecutionRequestV1.from_dict(request_value)
        evidence, events = self.bridge.authorization_evidence(request, cancel=cancel)
        packet = {
            "schema_version": 1,
            "scope": "kitpro-phase3b2e-live-authorization-request-v1",
            "vm_session_id": vm_session_id,
            "iso": dict(iso),
            "source": {
                "generation": evidence.source.generation,
                "evidence_sha256": evidence.binding.source_evidence_sha256,
                "generation_manifest_sha256": evidence.source.generation_manifest_sha256,
                "artifact_set_sha256": evidence.source.artifact_set_sha256,
                "rootfs_profile_sha256": evidence.source.rootfs_profile_sha256,
            },
            "target": dict(target),
            "guest_disk_inventory": list(
                getattr(self.bridge.backend.environment, "attestation", {}).get(
                    "guest_disk_inventory", []
                )
            ),
            "plan_sha256": evidence.binding.plan_sha256,
            "execution_request_sha256": evidence.binding.request_sha256,
            "qemu_environment_sha256": evidence.binding.environment_identity_sha256,
            "authorization_binding": asdict(evidence.binding),
            "authorization_binding_sha256": evidence.binding.binding_sha256,
            "request": request.to_dict(),
            "preflight_events": [asdict(event) for event in events],
        }
        return packet

    def validate_authorization_response(
        self,
        peer: PeerCredentials,
        request_value: dict[str, Any],
        authorization_value: dict[str, Any],
        *,
        expected_binding_sha256: str,
    ) -> SignedAuthorizationV1:
        """Authenticate a returned token without consuming it before commitment."""
        self.authenticate(peer)
        request = ExecutionRequestV1.from_dict(request_value)
        evidence, _ = self.bridge.authorization_evidence(request)
        if not hmac.compare_digest(evidence.binding.binding_sha256, expected_binding_sha256):
            raise AdapterError("authorization_mismatch", "authorization request changed")
        authorization = parse_signed_authorization(json.dumps(authorization_value))
        self.bridge.authorization.assert_current(authorization, evidence.binding)
        return authorization

    def authenticate(self, peer: PeerCredentials) -> None:
        if (
            peer.pid <= 0
            or peer.uid != self.expected_client_uid
            or not HEX64.fullmatch(peer.executable_sha256)
        ):
            raise AdapterError("service_client_invalid", "privileged service client is invalid")
        if not hmac.compare_digest(peer.executable_sha256, self.expected_client_executable_sha256):
            raise AdapterError("service_client_unauthorized", "privileged service client is denied")

    def provision_secret(
        self,
        peer: PeerCredentials,
        *,
        secret_fd: int,
        request_sha256: str,
        authorization_sha256: str,
        ttl_seconds: int,
    ) -> RuntimeSecretReference:
        """Import a protected descriptor; secret bytes never cross JSON or argv."""
        self.authenticate(peer)
        metadata = os.fstat(secret_fd)
        if metadata.st_size <= 0 or metadata.st_size > 4096:
            raise AdapterError("secret_invalid", "runtime secret descriptor is invalid")
        value = bytearray(os.pread(secret_fd, 4097, 0))
        try:
            if not value or len(value) > 4096 or b"\0" in value or b"\n" in value:
                raise AdapterError("secret_invalid", "runtime secret descriptor is invalid")
            return self.secrets.provision(
                value,
                request_sha256=request_sha256,
                authorization_sha256=authorization_sha256,
                ttl_seconds=ttl_seconds,
            )
        finally:
            value[:] = b"\0" * len(value)

    def execute(
        self,
        peer: PeerCredentials,
        envelope: dict[str, Any],
        *,
        emit: Callable[[ExecutionEventV1], None] | None = None,
        cancel: CancellationToken | None = None,
    ) -> ExecutionResponseV1:
        self.authenticate(peer)
        expected = {
            "schema_version",
            "adapter_api_version",
            "authorization_scope",
            "request",
            "authorization",
            "secret_reference",
        }
        if set(envelope) != expected:
            raise AdapterError("service_request_invalid", "service request fields are invalid")
        if (
            envelope["schema_version"] != SERVICE_SCHEMA_VERSION
            or envelope["adapter_api_version"] != ADAPTER_API_VERSION
            or envelope["authorization_scope"] != LIVE_AUTHORIZATION_SCOPE
        ):
            raise AdapterError(
                "service_request_unsupported", "service request version is unsupported"
            )
        request = ExecutionRequestV1.from_dict(envelope["request"])
        authorization = parse_signed_authorization(json.dumps(envelope["authorization"]))
        if authorization.scope != LIVE_AUTHORIZATION_SCOPE:
            raise AdapterError("authorization_invalid", "qualification authorization is not live")
        secret_value = envelope["secret_reference"]
        secret = None
        if secret_value is not None:
            if not isinstance(secret_value, dict) or set(secret_value) != {"provider", "reference"}:
                raise AdapterError("secret_invalid", "runtime secret reference is invalid")
            secret = RuntimeSecretReference(**secret_value)
        if self._active_request is not None:
            raise AdapterError("execution_busy", "another installation request is active")
        self._active_request = request.request_sha256
        try:
            if emit is None:
                return self.bridge.prepare(
                    request,
                    authorization=authorization,
                    secret=secret,
                    cancel=cancel,
                )
            return self.bridge.prepare(
                request,
                authorization=authorization,
                secret=secret,
                emit=emit,
                cancel=cancel,
            )
        finally:
            self._active_request = None


def service_safety_inventory() -> dict[str, object]:
    return {
        "schema_version": SERVICE_SCHEMA_VERSION,
        "accepted_authorization_scope": LIVE_AUTHORIZATION_SCOPE,
        "arbitrary_commands_accepted": False,
        "arbitrary_executable_paths_accepted": False,
        "ui_is_execution_authority": False,
        "secret_transport": "inherited-file-descriptor",
    }
