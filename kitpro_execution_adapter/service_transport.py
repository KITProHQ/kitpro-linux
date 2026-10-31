"""One-request Unix transport for the privileged guest service."""

from __future__ import annotations

import array
import hashlib
import json
import os
import socket
import struct
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .api import AdapterError, ExecutionEventV1, ExecutionRequestV1, canonical_json_bytes, redact
from .security import parse_signed_authorization
from .service import PeerCredentials, PrivilegedGuestService

MAX_REQUEST_BYTES = 4 * 1024 * 1024


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while block := os.pread(fd, 1024 * 1024, offset):
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


def peer_credentials(connection: socket.socket) -> PeerCredentials:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    executable_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        digest = _sha256_fd(executable_fd)
    finally:
        os.close(executable_fd)
    return PeerCredentials(pid, uid, gid, digest)


def _receive(connection: socket.socket) -> tuple[dict[str, Any], int | None]:
    descriptor_bytes = array.array("i").itemsize
    payload, ancillary, flags, _ = connection.recvmsg(
        MAX_REQUEST_BYTES + 1,
        socket.CMSG_SPACE(descriptor_bytes),
    )
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(payload) > MAX_REQUEST_BYTES:
        raise AdapterError("service_request_invalid", "service request exceeded its bound")
    descriptors: list[int] = []
    for level, kind, value in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received = array.array("i")
            received.frombytes(value[: len(value) - (len(value) % received.itemsize)])
            descriptors.extend(received)
    if len(descriptors) > 1:
        for descriptor in descriptors:
            os.close(descriptor)
        raise AdapterError("service_request_invalid", "service accepts at most one secret fd")
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        if descriptors:
            os.close(descriptors[0])
        raise AdapterError("service_request_invalid", "service request is invalid") from error
    if not isinstance(document, dict):
        if descriptors:
            os.close(descriptors[0])
        raise AdapterError("service_request_invalid", "service request is not an object")
    return document, descriptors[0] if descriptors else None


def serve_once(
    service: PrivilegedGuestService,
    socket_path: Path,
    *,
    secret_ttl_seconds: int = 120,
    response_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """Serve one authenticated execution request, then retire the socket."""
    socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        raise AdapterError("service_socket_invalid", "service socket path already exists")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        connection, _ = listener.accept()
        with connection:
            secret_fd: int | None = None
            stream_events = False
            client_connected = True

            def send(packet: dict[str, Any]) -> None:
                """Best-effort progress delivery must not control engine execution."""
                nonlocal client_connected
                if not client_connected:
                    return
                try:
                    connection.sendall(canonical_json_bytes(packet))
                except OSError:
                    # Submission commits the one-shot request. If the UI goes
                    # away after that boundary, the privileged engine must run
                    # to a terminal result and the host callback must still
                    # receive it. A progress consumer is never an execution
                    # control plane.
                    client_connected = False

            try:
                peer = peer_credentials(connection)
                service.authenticate(peer)
                envelope, secret_fd = _receive(connection)
                transport = envelope.pop("transport", None)
                if transport is not None:
                    if transport != {"stream_events": True}:
                        raise AdapterError(
                            "service_request_invalid", "service transport options are invalid"
                        )
                    stream_events = True
                request = envelope.get("request")
                authorization_value = envelope.get("authorization")
                if not isinstance(request, dict) or not isinstance(authorization_value, dict):
                    raise AdapterError("service_request_invalid", "service request is incomplete")
                authorization = parse_signed_authorization(json.dumps(authorization_value))
                if secret_fd is not None:
                    reference = service.provision_secret(
                        peer,
                        secret_fd=secret_fd,
                        request_sha256=ExecutionRequestV1.from_dict(request).request_sha256,
                        authorization_sha256=authorization.authorization_sha256,
                        ttl_seconds=secret_ttl_seconds,
                    )
                    envelope["secret_reference"] = {
                        "provider": reference.provider,
                        "reference": reference.reference,
                    }

                def emit(event: ExecutionEventV1) -> None:
                    if stream_events:
                        send({"kind": "event", "value": asdict(event)})

                response = redact(service.execute(peer, envelope, emit=emit).to_dict())
                assert isinstance(response, dict)
                wire_response = (
                    {"kind": "response", "value": response} if stream_events else response
                )
                send(wire_response)
                if response_callback is not None:
                    response_callback(response)
            except AdapterError as error:
                response = {
                    "status": "denied",
                    "error_code": error.code,
                    "error_message": str(error),
                }
                wire_response = (
                    {"kind": "response", "value": response} if stream_events else response
                )
                send(wire_response)
                if response_callback is not None:
                    response_callback(response)
            finally:
                if secret_fd is not None:
                    os.close(secret_fd)
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)
