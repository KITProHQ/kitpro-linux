"""Sealed-memfd runtime secret delivery for a privileged execution process."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Self

from .api import AdapterError, RuntimeSecretReference

MAX_SECRET_LIFETIME_SECONDS = 300


@dataclass(slots=True)
class _SecretRecord:
    fd: int
    request_sha256: str
    authorization_sha256: str | None
    expires_at: float
    consumed: bool = False
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class SecretLease:
    fd: int
    reference_sha256: str

    def diagnostic(self) -> dict[str, object]:
        return {"provider": "memfd", "reference": "[REDACTED]", "fd": "[REDACTED]"}


class ProtectedSecretBroker:
    """Keep synthetic or runtime credentials solely in sealed anonymous file descriptors."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._records: dict[str, _SecretRecord] = {}
        self._closed = False

    def provision(
        self,
        secret: bytes | bytearray,
        *,
        request_sha256: str,
        authorization_sha256: str | None = None,
        ttl_seconds: int,
    ) -> RuntimeSecretReference:
        if self._closed:
            raise AdapterError("secret_broker_closed", "runtime secret broker is closed")
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise AdapterError("secret_invalid", "runtime secret is missing")
        if ttl_seconds <= 0 or ttl_seconds > MAX_SECRET_LIFETIME_SECONDS:
            raise AdapterError("secret_invalid", "runtime secret lifetime is out of bounds")
        for value, name in ((request_sha256, "request"),):
            if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
                raise AdapterError("secret_invalid", f"runtime secret {name} binding is invalid")
        if authorization_sha256 is not None and (
            len(authorization_sha256) != 64
            or any(character not in "0123456789abcdef" for character in authorization_sha256)
        ):
            raise AdapterError("secret_invalid", "runtime secret authorization binding is invalid")
        fd = os.memfd_create(
            "kitpro-runtime-secret",
            os.MFD_CLOEXEC | getattr(os, "MFD_ALLOW_SEALING", 0),
        )
        try:
            os.write(fd, bytes(secret))
            os.lseek(fd, 0, os.SEEK_SET)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
        except Exception:
            os.close(fd)
            raise
        reference = secrets.token_urlsafe(32)
        self._records[reference] = _SecretRecord(
            fd,
            request_sha256,
            authorization_sha256,
            self.clock() + ttl_seconds,
        )
        return RuntimeSecretReference("memfd", reference)

    def available(
        self,
        reference: RuntimeSecretReference,
        *,
        request_sha256: str | None = None,
        authorization_sha256: str | None = None,
    ) -> bool:
        try:
            reference.validate()
        except AdapterError:
            return False
        record = self._records.get(reference.reference)
        return bool(
            record
            and not self._closed
            and not record.consumed
            and not record.revoked
            and self.clock() <= record.expires_at
            and (
                request_sha256 is None or hmac.compare_digest(record.request_sha256, request_sha256)
            )
            and (
                authorization_sha256 is None
                or (
                    record.authorization_sha256 is not None
                    and hmac.compare_digest(record.authorization_sha256, authorization_sha256)
                )
            )
        )

    def bind_authorization(
        self,
        reference: RuntimeSecretReference,
        *,
        request_sha256: str,
        authorization_sha256: str,
    ) -> None:
        record = self._records.get(reference.reference)
        if (
            record is None
            or record.consumed
            or record.revoked
            or self.clock() > record.expires_at
            or not hmac.compare_digest(record.request_sha256, request_sha256)
        ):
            raise AdapterError("secret_unavailable", "runtime secret cannot be bound")
        if len(authorization_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in authorization_sha256
        ):
            raise AdapterError("secret_invalid", "runtime secret authorization binding is invalid")
        if record.authorization_sha256 is not None:
            raise AdapterError("secret_rebound", "runtime secret authorization is already bound")
        record.authorization_sha256 = authorization_sha256

    @contextmanager
    def acquire(
        self,
        reference: RuntimeSecretReference,
        *,
        request_sha256: str,
        authorization_sha256: str,
    ) -> Iterator[SecretLease]:
        if not self.available(
            reference,
            request_sha256=request_sha256,
            authorization_sha256=authorization_sha256,
        ):
            raise AdapterError("secret_unavailable", "bound runtime secret is unavailable")
        record = self._records[reference.reference]
        record.consumed = True
        duplicate = os.dup(record.fd)
        os.set_inheritable(duplicate, False)
        os.lseek(duplicate, 0, os.SEEK_SET)
        lease = SecretLease(duplicate, hashlib.sha256(reference.reference.encode()).hexdigest())
        try:
            yield lease
        finally:
            os.close(duplicate)
            self._destroy(reference.reference)

    def revoke(self, reference: RuntimeSecretReference) -> None:
        record = self._records.get(reference.reference)
        if record is not None:
            record.revoked = True
            self._destroy(reference.reference)

    def _destroy(self, reference: str) -> None:
        record = self._records.pop(reference, None)
        if record is not None:
            os.close(record.fd)

    def close(self) -> None:
        for reference in list(self._records):
            self._destroy(reference)
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
