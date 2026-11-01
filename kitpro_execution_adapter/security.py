"""Cryptographically authenticated, VM-scoped qualification authorization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from .api import AdapterError, AuthorizationBindingV1, canonical_json_bytes

AUTHORIZATION_SCHEMA_VERSION = 1
AUTHORIZATION_SCOPE = "kitpro-phase3b2d-qualification-only"
LIVE_AUTHORIZATION_SCOPE = "kitpro-phase3b2e-live-vm-install-v1"
PHYSICAL_AUTHORIZATION_SCOPE = "kitpro-physical-console-install-v1"
MAX_AUTHORIZATION_LIFETIME_SECONDS = 300
HEX64 = re.compile(r"[0-9a-f]{64}")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _memfd(name: str, value: bytes) -> int:
    fd = os.memfd_create(name, os.MFD_CLOEXEC)
    os.write(fd, value)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def _run_openssl(arguments: list[str], pass_fds: tuple[int, ...]) -> None:
    completed = subprocess.run(
        ["/usr/bin/openssl", *arguments],
        pass_fds=pass_fds,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if completed.returncode:
        raise AdapterError("authorization_invalid", "authorization signature operation failed")


def public_key_id(public_key_pem: bytes) -> str:
    if b"BEGIN PUBLIC KEY" not in public_key_pem:
        raise AdapterError("authorization_invalid", "authorization public key is invalid")
    return _digest(public_key_pem)


def sign_document(private_key_fd: int, document: dict[str, object]) -> str:
    """Sign canonical JSON with an already-open private Ed25519 key."""
    payload_fd = _memfd("kitpro-signed-document", canonical_json_bytes(document))
    signature_fd = os.memfd_create("kitpro-document-signature", os.MFD_CLOEXEC)
    try:
        _run_openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                f"/proc/self/fd/{private_key_fd}",
                "-in",
                f"/proc/self/fd/{payload_fd}",
                "-out",
                f"/proc/self/fd/{signature_fd}",
            ],
            (private_key_fd, payload_fd, signature_fd),
        )
        os.lseek(signature_fd, 0, os.SEEK_SET)
        return base64.b64encode(os.read(signature_fd, 256)).decode("ascii")
    finally:
        os.close(payload_fd)
        os.close(signature_fd)


def verify_document(public_key_pem: bytes, document: dict[str, object], signature: str) -> None:
    """Verify canonical JSON Ed25519 evidence with a public key."""
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError) as error:
        raise AdapterError("signature_invalid", "signed evidence is invalid") from error
    public_fd = _memfd("kitpro-evidence-public-key", public_key_pem)
    payload_fd = _memfd("kitpro-signed-document", canonical_json_bytes(document))
    signature_fd = _memfd("kitpro-document-signature", signature_bytes)
    try:
        try:
            _run_openssl(
                [
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-rawin",
                    "-inkey",
                    f"/proc/self/fd/{public_fd}",
                    "-in",
                    f"/proc/self/fd/{payload_fd}",
                    "-sigfile",
                    f"/proc/self/fd/{signature_fd}",
                ],
                (public_fd, payload_fd, signature_fd),
            )
        except AdapterError as error:
            raise AdapterError("signature_invalid", "signed evidence is invalid") from error
    finally:
        os.close(public_fd)
        os.close(payload_fd)
        os.close(signature_fd)


class OperatorApprovalTicket:
    """Unserializable capability created only by a trusted approval gate."""

    __slots__ = ("_capability", "approval_id", "binding_sha256", "operator_uid")

    def __init__(
        self,
        approval_id: str,
        binding_sha256: str,
        operator_uid: int,
        capability: object,
    ) -> None:
        self.approval_id = approval_id
        self.binding_sha256 = binding_sha256
        self.operator_uid = operator_uid
        self._capability = capability


class OperatorApprovalGate:
    """Require an exact phrase on a pre-opened trusted terminal."""

    def __init__(self, *, expected_uid: int = 0, qualification_tests: bool = False) -> None:
        self.expected_uid = expected_uid
        self._qualification_tests = qualification_tests
        self._capability = object()
        self._consumed: set[str] = set()

    @staticmethod
    def phrase(binding: AuthorizationBindingV1) -> str:
        return f"AUTHORIZE VM {binding.binding_sha256}"

    def confirm_console(
        self,
        binding: AuthorizationBindingV1,
        *,
        terminal_fd: int,
        operator_uid: int,
    ) -> OperatorApprovalTicket:
        binding.validate()
        if operator_uid != self.expected_uid or not os.isatty(terminal_fd):
            raise AdapterError("operator_approval_invalid", "trusted operator console is required")
        os.write(terminal_fd, (self.phrase(binding) + "\n> ").encode())
        response = os.read(terminal_fd, 512).decode(errors="replace").strip()
        if not hmac.compare_digest(response, self.phrase(binding)):
            raise AdapterError("operator_approval_denied", "operator approval phrase did not match")
        return OperatorApprovalTicket(
            secrets.token_urlsafe(24), binding.binding_sha256, operator_uid, self._capability
        )

    def approve_for_qualification_test(
        self,
        binding: AuthorizationBindingV1,
        *,
        operator_uid: int,
    ) -> OperatorApprovalTicket:
        if not self._qualification_tests:
            raise AdapterError("operator_approval_invalid", "test approval is disabled")
        if operator_uid != self.expected_uid:
            raise AdapterError("operator_approval_invalid", "operator identity does not match")
        return OperatorApprovalTicket(
            secrets.token_urlsafe(24), binding.binding_sha256, operator_uid, self._capability
        )

    def consume(self, ticket: OperatorApprovalTicket, binding: AuthorizationBindingV1) -> str:
        if (
            not isinstance(ticket, OperatorApprovalTicket)
            or ticket._capability is not self._capability
        ):
            raise AdapterError("operator_approval_invalid", "operator approval is not authentic")
        if ticket.approval_id in self._consumed:
            raise AdapterError("operator_approval_replayed", "operator approval was already used")
        self._consumed.add(ticket.approval_id)
        if ticket.operator_uid != self.expected_uid or not hmac.compare_digest(
            ticket.binding_sha256, binding.binding_sha256
        ):
            raise AdapterError("operator_approval_mismatch", "operator approval binding changed")
        return _digest(ticket.approval_id.encode())


class LiveOperatorApprovalGate(OperatorApprovalGate):
    """Trusted-console approval whose phrase cannot be confused with qualification."""

    @staticmethod
    def phrase(binding: AuthorizationBindingV1) -> str:
        return f"AUTHORIZE LIVE VM INSTALL {binding.binding_sha256}"


class PhysicalOperatorApprovalGate(OperatorApprovalGate):
    """Bind physical-console approval to the exact media and target identity."""

    def __init__(
        self,
        *,
        media_sha256: str,
        expected_uid: int = 0,
        qualification_tests: bool = False,
    ) -> None:
        if not HEX64.fullmatch(media_sha256):
            raise AdapterError("operator_approval_invalid", "physical media digest is invalid")
        super().__init__(
            expected_uid=expected_uid,
            qualification_tests=qualification_tests,
        )
        self.media_sha256 = media_sha256

    def phrase(self, binding: AuthorizationBindingV1) -> str:
        binding.validate()
        return (
            f"AUTHORIZE PHYSICAL INSTALL MEDIA {self.media_sha256} "
            f"TARGET {binding.target_identity_sha256} BINDING {binding.binding_sha256}"
        )


@dataclass(frozen=True, slots=True)
class SignedAuthorizationV1:
    schema_version: int
    scope: str
    authorization_id: str
    binding_sha256: str
    operator_approval_sha256: str
    issuer_key_id: str
    issued_at: int
    expires_at: int
    signature: str

    def unsigned_document(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("signature")
        return value

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(asdict(self))

    @property
    def authorization_sha256(self) -> str:
        return _digest(self.canonical_bytes())

    def diagnostic(self) -> dict[str, object]:
        return {
            **self.unsigned_document(),
            "authorization_id": "[REDACTED]",
            "signature": "[REDACTED]",
            "authorization_sha256": self.authorization_sha256,
        }


class QualificationAuthorizationIssuer:
    """Sign only qualification-scoped evidence using a protected private-key FD."""

    authorization_scope = AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        private_key_fd: int,
        public_key_pem: bytes,
        approval_gate: OperatorApprovalGate,
        clock: Callable[[], float] = time.time,
    ) -> None:
        metadata = os.fstat(private_key_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise AdapterError(
                "authorization_credential_invalid",
                "authorization private key must be a private regular file",
            )
        self._private_key_fd = os.dup(private_key_fd)
        os.set_inheritable(self._private_key_fd, False)
        self.public_key_pem = bytes(public_key_pem)
        self.issuer_key_id = public_key_id(self.public_key_pem)
        self.approval_gate = approval_gate
        self.clock = clock

    def close(self) -> None:
        if self._private_key_fd >= 0:
            os.close(self._private_key_fd)
            self._private_key_fd = -1

    def issue(
        self,
        binding: AuthorizationBindingV1,
        approval: OperatorApprovalTicket,
        *,
        ttl_seconds: int,
    ) -> SignedAuthorizationV1:
        binding.validate()
        if ttl_seconds <= 0 or ttl_seconds > MAX_AUTHORIZATION_LIFETIME_SECONDS:
            raise AdapterError("authorization_invalid", "authorization lifetime is out of bounds")
        approval_sha256 = self.approval_gate.consume(approval, binding)
        issued_at = int(self.clock())
        unsigned = {
            "schema_version": AUTHORIZATION_SCHEMA_VERSION,
            "scope": self.authorization_scope,
            "authorization_id": secrets.token_urlsafe(32),
            "binding_sha256": binding.binding_sha256,
            "operator_approval_sha256": approval_sha256,
            "issuer_key_id": self.issuer_key_id,
            "issued_at": issued_at,
            "expires_at": issued_at + ttl_seconds,
        }
        signature = sign_document(self._private_key_fd, unsigned)
        return SignedAuthorizationV1(**unsigned, signature=signature)


class LiveAuthorizationIssuer(QualificationAuthorizationIssuer):
    """Issue only exact-scope live VM tokens with a distinct operator key."""

    authorization_scope = LIVE_AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        private_key_fd: int,
        public_key_pem: bytes,
        approval_gate: LiveOperatorApprovalGate,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            private_key_fd=private_key_fd,
            public_key_pem=public_key_pem,
            approval_gate=approval_gate,
            clock=clock,
        )


class PhysicalAuthorizationIssuer(QualificationAuthorizationIssuer):
    """Issue short-lived tokens only after exact physical-console approval."""

    authorization_scope = PHYSICAL_AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        private_key_fd: int,
        public_key_pem: bytes,
        approval_gate: PhysicalOperatorApprovalGate,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(approval_gate, PhysicalOperatorApprovalGate):
            raise AdapterError(
                "authorization_scope_invalid",
                "physical authorization requires the physical-console approval gate",
            )
        super().__init__(
            private_key_fd=private_key_fd,
            public_key_pem=public_key_pem,
            approval_gate=approval_gate,
            clock=clock,
        )


class AuthorizationConsumptionStore:
    """Atomically journal consumed authorization identifiers without bearer material."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise AdapterError("authorization_store_invalid", "authorization store is not private")

    def consume(self, authorization_id: str, audit: dict[str, object]) -> None:
        name = _digest(authorization_id.encode())
        path = self.root / name
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError as error:
            raise AdapterError(
                "authorization_replayed", "authorization was already consumed"
            ) from error
        try:
            os.write(fd, canonical_json_bytes(audit))
            os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


class ExecutionRevocationStore:
    """Persist request revocations without storing request or authorization contents."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise AdapterError("revocation_store_invalid", "revocation store is not private")

    def revoke(self, request_sha256: str, reason: str = "operator-revoked") -> None:
        if not HEX64.fullmatch(request_sha256):
            raise AdapterError("request_invalid", "revoked request digest is invalid")
        path = self.root / request_sha256
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            return
        try:
            os.write(
                fd,
                canonical_json_bytes(
                    {
                        "schema_version": 1,
                        "request_sha256": request_sha256,
                        "reason": reason,
                    }
                ),
            )
            os.fsync(fd)
        finally:
            os.close(fd)

    def assert_not_revoked(self, request_sha256: str) -> None:
        if not HEX64.fullmatch(request_sha256):
            raise AdapterError("request_invalid", "request digest is invalid")
        if (self.root / request_sha256).exists():
            raise AdapterError("request_revoked", "execution request was revoked")


class QualificationAuthorizationVerifier:
    """Verify and consume only non-production Phase 3B.2D authorization."""

    authorization_scope = AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        public_key_pem: bytes,
        consumption_store: AuthorizationConsumptionStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.public_key_pem = bytes(public_key_pem)
        self.issuer_key_id = public_key_id(self.public_key_pem)
        self.consumption_store = consumption_store
        self.clock = clock

    def _verify_current(
        self,
        token: SignedAuthorizationV1,
        binding: AuthorizationBindingV1,
    ) -> tuple[str, int]:
        binding.validate()
        if (
            token.schema_version != AUTHORIZATION_SCHEMA_VERSION
            or token.scope != self.authorization_scope
            or token.issuer_key_id != self.issuer_key_id
            or not HEX64.fullmatch(token.binding_sha256)
        ):
            raise AdapterError("authorization_invalid", "authorization metadata is unsupported")
        if not hmac.compare_digest(token.binding_sha256, binding.binding_sha256):
            raise AdapterError("authorization_mismatch", "authorization binding changed")
        now = int(self.clock())
        if token.expires_at <= token.issued_at or token.expires_at - token.issued_at > 300:
            raise AdapterError("authorization_invalid", "authorization lifetime is invalid")
        if now < token.issued_at - 5 or now > token.expires_at:
            raise AdapterError("authorization_expired", "authorization expired or is not current")
        try:
            verify_document(self.public_key_pem, token.unsigned_document(), token.signature)
        except AdapterError as error:
            raise AdapterError(
                "authorization_forged", "authorization signature is invalid"
            ) from error
        return token.authorization_sha256, now

    def assert_current(
        self,
        token: SignedAuthorizationV1,
        binding: AuthorizationBindingV1,
    ) -> str:
        """Recheck signature, binding, and expiry without consuming a second time."""
        authorization_sha256, _ = self._verify_current(token, binding)
        return authorization_sha256

    def verify_and_consume(
        self,
        token: SignedAuthorizationV1,
        binding: AuthorizationBindingV1,
    ) -> str:
        authorization_sha256, now = self._verify_current(token, binding)
        self.consumption_store.consume(
            token.authorization_id,
            {
                "schema_version": 1,
                "authorization_sha256": authorization_sha256,
                "binding_sha256": binding.binding_sha256,
                "consumed_at": now,
                "scope": self.authorization_scope,
            },
        )
        return authorization_sha256


class LiveAuthorizationVerifier(QualificationAuthorizationVerifier):
    """Verify only VM-live tokens signed by the separately pinned live authority."""

    authorization_scope = LIVE_AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        public_key_pem: bytes,
        consumption_store: AuthorizationConsumptionStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            public_key_pem=public_key_pem,
            consumption_store=consumption_store,
            clock=clock,
        )


class PhysicalAuthorizationVerifier(QualificationAuthorizationVerifier):
    """Verify only physical-console tokens from the per-boot ephemeral authority."""

    authorization_scope = PHYSICAL_AUTHORIZATION_SCOPE

    def __init__(
        self,
        *,
        public_key_pem: bytes,
        consumption_store: AuthorizationConsumptionStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(
            public_key_pem=public_key_pem,
            consumption_store=consumption_store,
            clock=clock,
        )


def load_private_key_fd(path: Path) -> int:
    """Open a private authority key without following links or exposing its contents."""
    if path.is_symlink():
        raise AdapterError("authorization_credential_invalid", "authorization key is a symlink")
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def parse_signed_authorization(document: str) -> SignedAuthorizationV1:
    try:
        value = json.loads(document)
        expected = {field.name for field in SignedAuthorizationV1.__dataclass_fields__.values()}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("fields")
        return SignedAuthorizationV1(**value)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise AdapterError("authorization_invalid", "authorization document is invalid") from error
