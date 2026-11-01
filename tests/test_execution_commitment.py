from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from kitpro_execution_adapter import (
    AdapterError,
    AuthorizationConsumptionStore,
    CommitmentAuditStore,
    EnvironmentEvidenceV1,
    ExecutionRequestV1,
    ExecutionRevocationStore,
    ExecutionSimulator,
    NonDestructivePrivilegedBridge,
    OperatorApprovalGate,
    ProtectedSecretBroker,
    QualificationAuthorizationIssuer,
    QualificationAuthorizationVerifier,
    RuntimeSecretReference,
    SourceEvidenceV1,
    TargetEvidenceV1,
    load_private_key_fd,
)
from kitpro_install_planner import plan_v1
from tests.test_shared_planner import pure_request
from tools.install.execution_commitment import (
    AuthoritativeEngineCommitment,
    SimulatedEngineFailure,
    connection_safety_inventory,
)


class FakeEngine:
    kitpro_non_destructive_fake = True

    def __init__(self, *, failure_after_commitment: bool | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.failure_after_commitment = failure_after_commitment

    def __call__(
        self,
        spec,
        plan,
        allow_disk_erase,
        source_metadata=None,
        stage_callback=None,
        administrator_password=None,
    ):
        self.calls.append(
            {
                "spec": spec,
                "plan": plan,
                "allow_disk_erase": allow_disk_erase,
                "source_metadata": source_metadata,
                "password": administrator_password,
            }
        )
        if stage_callback:
            stage_callback("partitioning")
        if self.failure_after_commitment is not None:
            raise SimulatedEngineFailure(
                "synthetic-password must never escape",
                after_commitment=self.failure_after_commitment,
            )
        return Path("/run/kitpro/fake-report.json"), {
            "schema_version": 1,
            "simulation_only": True,
            "result": "fake-complete",
        }


class Backend:
    def __init__(self, request: ExecutionRequestV1, broker: ProtectedSecretBroker) -> None:
        plan = request.plan["plan"]
        target = plan["target"]
        self.target = TargetEvidenceV1(
            target["path"],
            target["target_type"],
            target["size_bytes"],
            target["identity"],
            target.get("marker_sha256"),
            "f" * 64,
        )
        self.source = SourceEvidenceV1(
            "kitpro-production-verifier-v1",
            plan["repository_generation"],
            plan["repository"]["generation_manifest_sha256"],
            plan["repository"]["artifact_set_sha256"],
            plan["rootfs"]["profile_sha256"],
            "1" * 64,
        )
        self.environment = EnvironmentEvidenceV1(
            "kitpro-qemu-environment-verifier-v1",
            "kitpro-phase3b2d-qemu-v1",
            "2" * 64,
            "3" * 64,
            "4" * 64,
        )
        self.broker = broker
        self.environment_calls = 0
        self.after_second_environment = None

    def verify_source(self, request):
        del request
        return self.source

    def verify_target(self, request):
        del request
        return self.target

    def verify_plan(self, request):
        del request

    def verify_environment(self, request, target):
        del request, target
        self.environment_calls += 1
        if self.environment_calls == 2 and self.after_second_environment:
            self.after_second_environment()
        return self.environment

    def secret_available(self, reference: RuntimeSecretReference) -> bool:
        return self.broker.available(reference)


def request_fixture() -> ExecutionRequestV1:
    pure = pure_request()
    planning = plan_v1(pure)
    backend_spec = dict(pure.install_spec)
    backend_spec["disk"] = dict(backend_spec["disk"])
    backend_spec["disk"]["minimum_capacity_gib"] = backend_spec["disk"].pop(
        "minimum_capacity_bytes"
    ) // (1024**3)
    return ExecutionRequestV1.create(
        installation_spec=backend_spec,
        installation_spec_sha256=planning.plan["install_spec_sha256"],
        plan=planning.to_dict(),
        plan_sha256=planning.result_sha256,
        installer_version="0.7.0.dev0",
        planner_version="1.0.0",
        planner_api_version=1,
        contract_schema_version=1,
        runtime_secret_required=True,
    )


def keys(root: Path) -> tuple[Path, bytes]:
    private = root / "authority.pem"
    public = root / "authority.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    private.chmod(0o600)
    return private, public.read_bytes()


def authorized_bridge(tmp_path: Path, clock: list[float], fake: FakeEngine):
    request = request_fixture()
    broker = ProtectedSecretBroker(clock=lambda: clock[0])
    backend = Backend(request, broker)
    secret = broker.provision(
        b"synthetic-password", request_sha256=request.request_sha256, ttl_seconds=240
    )
    evidence, _ = ExecutionSimulator(backend, authority=None).preflight_evidence(  # type: ignore[arg-type]
        request, secret=secret
    )
    backend.environment_calls = 0
    private, public = keys(tmp_path)
    gate = OperatorApprovalGate(expected_uid=os.getuid(), qualification_tests=True)
    key_fd = load_private_key_fd(private)
    issuer = QualificationAuthorizationIssuer(
        private_key_fd=key_fd,
        public_key_pem=public,
        approval_gate=gate,
        clock=lambda: clock[0],
    )
    os.close(key_fd)
    approval = gate.approve_for_qualification_test(evidence.binding, operator_uid=os.getuid())
    token = issuer.issue(evidence.binding, approval, ttl_seconds=60)
    issuer.close()
    broker.bind_authorization(
        secret,
        request_sha256=request.request_sha256,
        authorization_sha256=token.authorization_sha256,
    )
    revocations = ExecutionRevocationStore(tmp_path / "revoked")
    bridge = NonDestructivePrivilegedBridge(
        backend=backend,
        authorization=QualificationAuthorizationVerifier(
            public_key_pem=public,
            consumption_store=AuthorizationConsumptionStore(tmp_path / "consumed"),
            clock=lambda: clock[0],
        ),
        secrets=broker,
        audit=CommitmentAuditStore(tmp_path / "audit"),
        commitment=AuthoritativeEngineCommitment(fake),
        revocations=revocations,
    )
    return request, backend, secret, token, bridge, revocations


def test_complete_bridge_to_fake_engine_maps_exact_authoritative_arguments(tmp_path: Path) -> None:
    fake = FakeEngine()
    request, _, secret, token, bridge, _ = authorized_bridge(tmp_path, [1_800_000_000.0], fake)
    response = bridge.prepare(request, authorization=token, secret=secret)
    assert response.status == "simulated"
    assert response.error_code is None
    assert not response.disk_may_be_modified
    assert not response.destructive_execution_performed
    assert [event.stage for event in response.events if event.stage.startswith("engine:")] == [
        "engine:partitioning"
    ]
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["plan"] == request.plan["plan"]
    assert call["allow_disk_erase"] is True
    assert call["password"] == "synthetic-password"
    assert call["source_metadata"]["generation"] == "0.1-dev-g0010"


def test_authorization_expiry_is_rechecked_at_commitment(tmp_path: Path) -> None:
    clock = [1_800_000_000.0]
    fake = FakeEngine()
    request, backend, secret, token, bridge, _ = authorized_bridge(tmp_path, clock, fake)
    backend.after_second_environment = lambda: clock.__setitem__(0, clock[0] + 61)
    response = bridge.prepare(request, authorization=token, secret=secret)
    assert response.status == "denied"
    assert response.error_code == "authorization_expired"
    assert fake.calls == []


def test_request_revocation_immediately_before_commitment_fails_closed(tmp_path: Path) -> None:
    clock = [1_800_000_000.0]
    fake = FakeEngine()
    request, backend, secret, token, bridge, revocations = authorized_bridge(tmp_path, clock, fake)
    backend.after_second_environment = lambda: revocations.revoke(request.request_sha256)
    response = bridge.prepare(request, authorization=token, secret=secret)
    assert response.status == "denied"
    assert response.error_code == "request_revoked"
    assert fake.calls == []


@pytest.mark.parametrize("after_commitment", [False, True])
def test_fake_failure_reports_hypothetical_commit_state_without_claiming_execution(
    tmp_path: Path, after_commitment: bool
) -> None:
    fake = FakeEngine(failure_after_commitment=after_commitment)
    request, _, secret, token, bridge, _ = authorized_bridge(tmp_path, [1_800_000_000.0], fake)
    response = bridge.prepare(request, authorization=token, secret=secret)
    assert response.status == "failed"
    assert response.error_code == "simulated_engine_failure"
    assert response.disk_may_be_modified is after_commitment
    assert not response.destructive_execution_performed
    assert "synthetic-password" not in (response.error_message or "")


def test_commitment_connector_rejects_any_unmarked_engine() -> None:
    def unmarked(*args, **kwargs):
        del args, kwargs

    with pytest.raises(AdapterError, match="non-destructive fake"):
        AuthoritativeEngineCommitment(unmarked)  # type: ignore[arg-type]
    inventory = connection_safety_inventory()
    assert inventory["production_engine_imported"] is False
    assert inventory["production_factory_available"] is False
    assert inventory["arbitrary_command_runner"] is False
