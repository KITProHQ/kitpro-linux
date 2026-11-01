"""Composition root for the VM-only privileged installation service."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from kitpro_execution_adapter import (
    AdapterError,
    AuthorizationConsumptionStore,
    CommitmentAuditStore,
    ExecutionRevocationStore,
    LiveAuthorizationVerifier,
    LivePrivilegedBridge,
    PHYSICAL_AUTHORIZATION_SCOPE,
    PhysicalAuthorizationVerifier,
    PhysicalPrivilegedBridge,
    PrivilegedGuestService,
    ProtectedSecretBroker,
    public_key_id,
)
from tools.install.execution_adapter import (
    AuthoritativeExecutionBackend,
    SignedQemuEnvironmentVerifier,
    PhysicalConsoleEnvironmentVerifier,
)
from tools.install.execution_commitment import create_live_engine_commitment

LIVE_AUTHORIZATION_PUBLIC_KEY = Path("/etc/kitpro-installer/phase3b2e-live-authorization.pub.pem")
LIVE_HOST_EVIDENCE_PUBLIC_KEY = Path("/etc/kitpro-installer/phase3b2e-host-evidence.pub.pem")
STATE_ROOT = Path("/var/lib/kitpro-installer/live-execution-v1")
PHYSICAL_STATE_ROOT = Path("/var/lib/kitpro-installer/physical-execution-v1")
BACKEND_ROOT = Path("/opt/kitpro-linux")
BACKEND_STATE_PATHS = (
    BACKEND_ROOT / ".state/production-verification",
    BACKEND_ROOT / ".state/phase3",
)
HOST_EVIDENCE_ROLE = "host-target-attestation"


def prepare_backend_state_paths() -> tuple[Path, ...]:
    """Create only the backend state roots allowed by the systemd sandbox."""
    if BACKEND_ROOT.is_symlink() or not BACKEND_ROOT.is_dir():
        raise AdapterError("service_state_invalid", "backend root is unavailable")
    state_parent = BACKEND_ROOT / ".state"
    if state_parent.is_symlink():
        raise AdapterError("service_state_invalid", "backend state root is a symlink")
    state_parent.mkdir(mode=0o700, exist_ok=True)
    for path in BACKEND_STATE_PATHS:
        if path.is_symlink():
            raise AdapterError("service_state_invalid", "backend state path is a symlink")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise AdapterError("service_state_invalid", "backend state path is not private")
        try:
            path.resolve(strict=True).relative_to(state_parent.resolve(strict=True))
        except ValueError as error:
            raise AdapterError("service_state_invalid", "backend state path escaped") from error
    return BACKEND_STATE_PATHS


def build_live_service(
    *,
    host_attestation: dict[str, Any],
    development_iso_sha256: str,
    expected_client_executable_sha256: str,
    broker: ProtectedSecretBroker | None = None,
    authorization_public_key_path: Path = LIVE_AUTHORIZATION_PUBLIC_KEY,
    host_evidence_public_key_path: Path = LIVE_HOST_EVIDENCE_PUBLIC_KEY,
    state_root: Path = STATE_ROOT,
    expected_host_scope: str = "phase3b2e-live-vm-candidate-v1",
    commitment: object | None = None,
) -> PrivilegedGuestService:
    """Build the only live engine connection; callers must already be privileged."""
    if os.geteuid() != 0:
        raise AdapterError("privilege_required", "live installation service requires root")
    for key_path in (authorization_public_key_path, host_evidence_public_key_path):
        if key_path.is_symlink() or not key_path.is_file():
            raise AdapterError("authorization_key_missing", "live public key is unavailable")
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_root.is_symlink() or state_root.stat().st_mode & 0o077:
        raise AdapterError("service_state_invalid", "live service state directory is unsafe")
    prepare_backend_state_paths()
    secrets = broker or ProtectedSecretBroker()
    environment = SignedQemuEnvironmentVerifier(
        host_attestation,
        public_key_pem=host_evidence_public_key_path.read_bytes(),
        expected_iso_sha256=development_iso_sha256,
        expected_scope=expected_host_scope,
        expected_authority_role=HOST_EVIDENCE_ROLE,
        expected_issuer_key_id=public_key_id(host_evidence_public_key_path.read_bytes()),
    )
    backend = AuthoritativeExecutionBackend(environment=environment, secrets=secrets)
    authorization = LiveAuthorizationVerifier(
        public_key_pem=authorization_public_key_path.read_bytes(),
        consumption_store=AuthorizationConsumptionStore(state_root / "consumed"),
    )
    bridge = LivePrivilegedBridge(
        backend=backend,
        authorization=authorization,
        secrets=secrets,
        audit=CommitmentAuditStore(state_root / "commitment"),
        commitment=commitment or create_live_engine_commitment(),
        revocations=ExecutionRevocationStore(state_root / "revoked"),
    )
    return PrivilegedGuestService(
        bridge=bridge,
        secrets=secrets,
        expected_client_uid=0,
        expected_client_executable_sha256=expected_client_executable_sha256,
    )


def build_physical_service(
    *,
    media_sha256: str,
    installation_media_paths: set[str] | frozenset[str],
    authorization_public_key_pem: bytes,
    expected_client_executable_sha256: str,
    broker: ProtectedSecretBroker | None = None,
    state_root: Path = PHYSICAL_STATE_ROOT,
    disk_inventory: Callable[[], list[dict[str, object]]] | None = None,
    commitment: object | None = None,
) -> PrivilegedGuestService:
    """Compose physical execution from a per-boot public authority key only."""
    if os.geteuid() != 0:
        raise AdapterError("privilege_required", "physical installation service requires root")
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_root.is_symlink() or state_root.stat().st_mode & 0o077:
        raise AdapterError("service_state_invalid", "physical service state directory is unsafe")
    prepare_backend_state_paths()
    secrets = broker or ProtectedSecretBroker()
    environment = PhysicalConsoleEnvironmentVerifier(
        media_sha256=media_sha256,
        installation_media_paths=installation_media_paths,
        disk_inventory=disk_inventory,
    )
    backend = AuthoritativeExecutionBackend(environment=environment, secrets=secrets)
    authorization = PhysicalAuthorizationVerifier(
        public_key_pem=bytes(authorization_public_key_pem),
        consumption_store=AuthorizationConsumptionStore(state_root / "consumed"),
    )
    bridge = PhysicalPrivilegedBridge(
        backend=backend,
        authorization=authorization,
        secrets=secrets,
        audit=CommitmentAuditStore(state_root / "commitment"),
        commitment=commitment
        or create_live_engine_commitment(
            required_environment_profile="kitpro-physical-console-v1"
        ),
        revocations=ExecutionRevocationStore(state_root / "revoked"),
    )
    return PrivilegedGuestService(
        bridge=bridge,
        secrets=secrets,
        expected_client_uid=0,
        expected_client_executable_sha256=expected_client_executable_sha256,
        accepted_authorization_scope=PHYSICAL_AUTHORIZATION_SCOPE,
    )


def live_service_permissions() -> dict[str, object]:
    return {
        "requires_root": True,
        "root_reason": [
            "inspect and hold open the authorized block target while the partitioner owns its lock",
            "invoke the existing engine's partition, mount, deployment, and bootloader operations",
            "write durable replay, revocation, commitment, and receipt evidence",
        ],
        "accepted_client_uid": 0,
        "ui_direct_access": False,
        "arbitrary_commands": False,
    }
