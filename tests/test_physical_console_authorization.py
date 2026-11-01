from __future__ import annotations

import importlib.util
import hashlib
import os
import subprocess
from dataclasses import asdict
from pathlib import Path

import pytest

from kitpro_execution_adapter import (
    AdapterError,
    AuthorizationBindingV1,
    AuthorizationConsumptionStore,
    PHYSICAL_AUTHORIZATION_SCOPE,
    PeerCredentials,
    PhysicalAuthorizationIssuer,
    PhysicalAuthorizationVerifier,
    PhysicalOperatorApprovalGate,
    PrivilegedGuestService,
    ProtectedSecretBroker,
    EnvironmentEvidenceV1,
    load_private_key_fd,
)
from tests.test_execution_commitment import request_fixture
from tools.install.execution_adapter import PhysicalConsoleEnvironmentVerifier
from tools.install.execution_commitment import (
    LiveAuthoritativeEngineCommitment,
    create_live_engine_commitment,
)
from tools.install import live_service
from tools import phase3b2b_prep

ROOT = Path(__file__).resolve().parents[1]
PHYSICAL_ENTRYPOINT = (
    ROOT
    / "archiso/kitpro-installer-3b2e-overlay/airootfs/usr/local/lib/kitpro-linux"
    / "physical-console-execution.py"
)


def _physical_entrypoint_module():
    specification = importlib.util.spec_from_file_location(
        "kitpro_physical_console_execution_test", PHYSICAL_ENTRYPOINT
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _keys(root: Path) -> tuple[Path, bytes]:
    private = root / "physical.pem"
    public = root / "physical.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "/usr/bin/openssl",
            "pkey",
            "-in",
            str(private),
            "-pubout",
            "-out",
            str(public),
        ],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    return private, public.read_bytes()


def _binding() -> AuthorizationBindingV1:
    return AuthorizationBindingV1(
        request_sha256="1" * 64,
        installation_spec_sha256="2" * 64,
        plan_sha256="3" * 64,
        source_evidence_sha256="4" * 64,
        target_identity_sha256="5" * 64,
        environment_identity_sha256="6" * 64,
        installer_version="1.2.0",
        planner_version="1.8.0",
        planner_api_version=1,
    )


def test_physical_phrase_and_token_bind_media_target_and_distinct_scope(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    media_sha256 = "a" * 64
    gate = PhysicalOperatorApprovalGate(
        media_sha256=media_sha256,
        expected_uid=os.getuid(),
        qualification_tests=True,
    )
    binding = _binding()
    phrase = gate.phrase(binding)
    assert media_sha256 in phrase
    assert binding.target_identity_sha256 in phrase
    assert binding.binding_sha256 in phrase

    private, public = _keys(tmp_path)
    key_fd = load_private_key_fd(private)
    issuer = PhysicalAuthorizationIssuer(
        private_key_fd=key_fd,
        public_key_pem=public,
        approval_gate=gate,
        clock=lambda: now[0],
    )
    os.close(key_fd)
    approval = gate.approve_for_qualification_test(binding, operator_uid=os.getuid())
    token = issuer.issue(binding, approval, ttl_seconds=60)
    issuer.close()
    assert token.scope == PHYSICAL_AUTHORIZATION_SCOPE

    verifier = PhysicalAuthorizationVerifier(
        public_key_pem=public,
        consumption_store=AuthorizationConsumptionStore(tmp_path / "consumed"),
        clock=lambda: now[0],
    )
    assert verifier.verify_and_consume(token, binding) == token.authorization_sha256
    with pytest.raises(AdapterError, match="already consumed"):
        verifier.verify_and_consume(token, binding)


def test_physical_environment_binds_media_inventory_and_target() -> None:
    request = request_fixture()
    planned = request.plan["plan"]["target"]
    from kitpro_execution_adapter import TargetEvidenceV1

    target = TargetEvidenceV1(
        planned["path"],
        planned["target_type"],
        planned["size_bytes"],
        planned["identity"],
        planned.get("marker_sha256"),
        "f" * 64,
    )
    inventory = [
        {
            "path": target.path,
            "size_bytes": target.size_bytes,
            "serial": target.identity.get("serial"),
            "read_only": False,
        },
        {"path": "/dev/sr0", "size_bytes": 2**30, "serial": None, "read_only": True},
    ]
    verifier = PhysicalConsoleEnvironmentVerifier(
        media_sha256="a" * 64,
        installation_media_paths={"/dev/sr0"},
        disk_inventory=lambda: inventory,
    )
    evidence = verifier.verify(request, target)
    assert evidence.profile == "kitpro-physical-console-v1"
    assert evidence.boot_artifact_sha256 == "a" * 64

    with pytest.raises(AdapterError, match="not approved"):
        EnvironmentEvidenceV1(
            "kitpro-physical-console-environment-verifier-v1",
            "kitpro-phase3b2e-qemu-v1",
            "a" * 64,
            "b" * 64,
            "c" * 64,
        ).validate()

    protected = PhysicalConsoleEnvironmentVerifier(
        media_sha256="a" * 64,
        installation_media_paths={target.path},
        disk_inventory=lambda: inventory,
    )
    with pytest.raises(AdapterError, match="installation media cannot"):
        protected.verify(request, target)

    changed = [dict(inventory[0], serial="replacement"), inventory[1]]
    with pytest.raises(AdapterError, match="identity changed"):
        PhysicalConsoleEnvironmentVerifier(
            media_sha256="a" * 64,
            installation_media_paths={"/dev/sr0"},
            disk_inventory=lambda: changed,
        ).verify(request, target)


def test_service_scope_is_configured_without_changing_vm_default(tmp_path: Path) -> None:
    class Bridge:
        def prepare(self, request, *, authorization, secret, cancel, emit=None):
            del request, authorization, secret, cancel, emit
            return "accepted"

    private, public = _keys(tmp_path)
    gate = PhysicalOperatorApprovalGate(
        media_sha256="a" * 64,
        expected_uid=os.getuid(),
        qualification_tests=True,
    )
    key_fd = load_private_key_fd(private)
    issuer = PhysicalAuthorizationIssuer(
        private_key_fd=key_fd,
        public_key_pem=public,
        approval_gate=gate,
        clock=lambda: 1_800_000_000,
    )
    os.close(key_fd)
    approval = gate.approve_for_qualification_test(_binding(), operator_uid=os.getuid())
    token = issuer.issue(_binding(), approval, ttl_seconds=60)
    issuer.close()
    request = request_fixture()
    envelope = {
        "schema_version": 1,
        "adapter_api_version": 1,
        "authorization_scope": token.scope,
        "request": request.to_dict(),
        "authorization": asdict(token),
        "secret_reference": None,
    }
    peer = PeerCredentials(1, 0, 0, "b" * 64)
    physical = PrivilegedGuestService(
        bridge=Bridge(),  # type: ignore[arg-type]
        secrets=ProtectedSecretBroker(),
        expected_client_uid=0,
        expected_client_executable_sha256="b" * 64,
        accepted_authorization_scope=PHYSICAL_AUTHORIZATION_SCOPE,
    )
    assert physical.execute(peer, envelope) == "accepted"
    vm_default = PrivilegedGuestService(
        bridge=Bridge(),  # type: ignore[arg-type]
        secrets=ProtectedSecretBroker(),
        expected_client_uid=0,
        expected_client_executable_sha256="b" * 64,
    )
    with pytest.raises(AdapterError, match="unsupported"):
        vm_default.execute(peer, envelope)


def test_service_exposes_verifier_owned_binding_without_authority_or_secret() -> None:
    request = request_fixture()

    class Bridge:
        def authorization_evidence(self, actual, *, cancel=None):
            del cancel
            assert actual == request
            from kitpro_execution_adapter import ExecutionEventV1, PreflightEvidenceV1
            from tests.test_execution_commitment import Backend

            broker = ProtectedSecretBroker()
            backend = Backend(request, broker)
            binding = _binding()
            return (
                PreflightEvidenceV1(
                    binding,
                    backend.source,
                    backend.target,
                    backend.environment,
                ),
                (ExecutionEventV1(1, "environment", "passed", "physical environment"),),
            )

    service = PrivilegedGuestService(
        bridge=Bridge(),  # type: ignore[arg-type]
        secrets=ProtectedSecretBroker(),
        expected_client_uid=0,
        expected_client_executable_sha256="b" * 64,
        accepted_authorization_scope=PHYSICAL_AUTHORIZATION_SCOPE,
    )
    binding = service.authorization_binding(
        PeerCredentials(1, 0, 0, "b" * 64), request.to_dict()
    )
    assert binding == _binding()


def test_live_factory_accepts_only_named_vm_or_physical_profile() -> None:
    physical = create_live_engine_commitment(
        required_environment_profile="kitpro-physical-console-v1"
    )
    assert isinstance(physical, LiveAuthoritativeEngineCommitment)
    assert physical._required_environment_profile == "kitpro-physical-console-v1"
    assert create_live_engine_commitment()._required_environment_profile == (
        "kitpro-phase3b2e-qemu-v1"
    )
    with pytest.raises(AdapterError, match="unsupported"):
        create_live_engine_commitment(required_environment_profile="untrusted")


def test_physical_service_uses_public_key_scope_and_physical_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, public = _keys(tmp_path)
    monkeypatch.setattr(live_service.os, "geteuid", lambda: 0)
    monkeypatch.setattr(live_service, "prepare_backend_state_paths", lambda: ())

    class Commitment:
        pass

    service = live_service.build_physical_service(
        media_sha256="a" * 64,
        installation_media_paths={"/dev/sr0"},
        authorization_public_key_pem=public,
        expected_client_executable_sha256="b" * 64,
        state_root=tmp_path / "state",
        disk_inventory=lambda: [],
        commitment=Commitment(),
    )
    assert service.accepted_authorization_scope == PHYSICAL_AUTHORIZATION_SCOPE
    assert service.bridge.authorization.authorization_scope == PHYSICAL_AUTHORIZATION_SCOPE
    assert service.bridge.backend.environment.media_sha256 == "a" * 64


def test_physical_media_hash_uses_only_the_iso_boundary(tmp_path: Path) -> None:
    module = _physical_entrypoint_module()
    media = tmp_path / "usb.img"
    media.write_bytes(b"qualified-iso-bytes" + b"unrelated-device-tail")
    assert module.sha256_file(media, length=len(b"qualified-iso-bytes")) == hashlib.sha256(
        b"qualified-iso-bytes"
    ).hexdigest()


def test_physical_console_uses_single_word_confirmation() -> None:
    module = _physical_entrypoint_module()
    gate = module.PhysicalConsoleApprovalGate(media_sha256="a" * 64)
    binding = _binding()
    assert gate.phrase(binding) == "AUTHORIZE"


def test_physical_media_falls_back_to_archiso_boot_uuid_after_copytoram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _physical_entrypoint_module()
    media = tmp_path / "usb.img"
    partition = tmp_path / "usb-partition.img"
    qualified = b"qualified-iso-with-appended-efi"
    media.write_bytes(qualified + b"unrelated-device-tail")
    partition.write_bytes(qualified)
    command_line = tmp_path / "cmdline"
    command_line.write_text("quiet archisosearchuuid=2026-10-07-19-03-57-00\n")
    monkeypatch.setattr(module, "KERNEL_COMMAND_LINE", command_line)
    monkeypatch.setattr(module, "optional_command", lambda arguments: None)
    monkeypatch.setattr(module, "_parent_device", lambda source: media)

    def fake_command(arguments: list[str]) -> str:
        if arguments[1:3] == ["-t", "UUID=2026-10-07-19-03-57-00"]:
            return f"{media}\n{partition}"
        if "TYPE" in arguments and arguments[0] == "/usr/bin/blkid":
            return "iso9660"
        if arguments[-2:] == ["TYPE", str(media)]:
            return "disk"
        if arguments[-2:] == ["TRAN", str(media)]:
            return "usb"
        if arguments[-2:] == ["RM", str(media)]:
            return "1"
        if "FSSIZE" in arguments:
            return str(len(qualified))
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "command", fake_command)
    digest, protected_paths = module.physical_media_identity()
    assert digest == hashlib.sha256(qualified).hexdigest()
    assert protected_paths == frozenset({str(media)})


def test_physical_media_rejects_ambiguous_boot_uuid_devices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _physical_entrypoint_module()
    first = tmp_path / "first.img"
    second = tmp_path / "second.img"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    command_line = tmp_path / "cmdline"
    command_line.write_text("archisosearchuuid=2026-10-07-19-03-57-00\n")
    monkeypatch.setattr(module, "KERNEL_COMMAND_LINE", command_line)
    monkeypatch.setattr(module, "optional_command", lambda arguments: None)
    monkeypatch.setattr(module, "_parent_device", lambda source: source)

    def fake_command(arguments: list[str]) -> str:
        if arguments[1:3] == ["-t", "UUID=2026-10-07-19-03-57-00"]:
            return f"{first}\n{second}"
        if "TYPE" in arguments and arguments[0] == "/usr/bin/blkid":
            return "iso9660"
        raise AssertionError(arguments)

    monkeypatch.setattr(module, "command", fake_command)
    with pytest.raises(RuntimeError, match="identity is ambiguous"):
        module.physical_media_device()


def test_physical_media_rejects_missing_boot_uuid_after_copytoram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _physical_entrypoint_module()
    command_line = tmp_path / "cmdline"
    command_line.write_text("quiet kitpro.mode=install\n")
    monkeypatch.setattr(module, "KERNEL_COMMAND_LINE", command_line)
    monkeypatch.setattr(module, "optional_command", lambda arguments: None)
    with pytest.raises(RuntimeError, match="archisosearchuuid is missing or ambiguous"):
        module.physical_media_device()


def test_physical_and_vm_services_are_mutually_exclusive_and_tty_bound() -> None:
    vm_unit = (
        ROOT
        / "archiso/kitpro-installer-3b2e-overlay/airootfs/etc/systemd/system"
        / "kitpro-phase3b2e-live-execution.service"
    ).read_text()
    physical_unit = (
        ROOT
        / "archiso/kitpro-installer-3b2e-overlay/airootfs/etc/systemd/system"
        / "kitpro-physical-console-execution.service"
    ).read_text()
    assert "ConditionVirtualization=vm" in vm_unit
    assert "ConditionVirtualization=!vm" in physical_unit
    assert "StandardInput=tty-force" in physical_unit
    assert "TTYPath=/dev/tty9" in physical_unit
    assert "Conflicts=getty@tty9.service" in physical_unit
    assert 'subprocess.run(["/usr/bin/chvt", "9"], check=True)' in PHYSICAL_ENTRYPOINT.read_text()
    assert "physical-console-execution.py" in physical_unit
    assert "PRIVATE KEY" not in PHYSICAL_ENTRYPOINT.read_text()


def test_final_media_profile_binds_candidate_17_physical_runtime() -> None:
    try:
        phase3b2b_prep.configure_linux_1_1_final_media()
        assert phase3b2b_prep.MEDIA_VERSION == "1.1.0-rc1-candidate.17"
        assert phase3b2b_prep.RUNTIME_LOCK_NAME == (
            "runtime-lock.linux-1.1-final-media-candidate.17.json"
        )
        assert phase3b2b_prep.EXPECTED_ADAPTER == {
            "api_version": 1,
            "source_commit": "a7402fcb8e56aeb8fbefc33542414f297e44d32c",
            "version": "0.5.1",
        }
        assert phase3b2b_prep.EXPECTED_INSTALLER == {
            "source_commit": "776e207fdc84d78b65b8e1e3759b5eb1cf4414af",
            "version": "1.2.0",
        }
    finally:
        importlib.reload(phase3b2b_prep)
