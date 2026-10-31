"""Bounded authenticated protocol for one host and one installer VM session."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
from dataclasses import dataclass
from typing import Any

from .api import AdapterError, canonical_json_bytes

CHANNEL_SCHEMA_VERSION = 1
MAX_CHANNEL_MESSAGE_BYTES = 1024 * 1024
ROLE_KINDS = {
    "guest": frozenset({"authorization_request", "status"}),
    "host": frozenset({"authorization", "abort"}),
}


def channel_key_sha256(key: bytes) -> str:
    if len(key) != 32:
        raise AdapterError("channel_key_invalid", "VM channel key must contain 32 bytes")
    return hashlib.sha256(key).hexdigest()


@dataclass(frozen=True, slots=True)
class ChannelMessageV1:
    sender: str
    kind: str
    sequence: int
    session_id: str
    request_sha256: str | None
    payload: dict[str, Any]
    mac: str


class AuthenticatedVmChannel:
    """Exchange only authorization workflow messages for one signed VM session."""

    def __init__(
        self,
        connection: socket.socket,
        *,
        key: bytes,
        session_id: str,
        local_role: str,
    ) -> None:
        if local_role not in ROLE_KINDS:
            raise AdapterError("channel_role_invalid", "VM channel role is unsupported")
        if len(session_id) != 64 or any(value not in "0123456789abcdef" for value in session_id):
            raise AdapterError("channel_session_invalid", "VM channel session is invalid")
        channel_key_sha256(key)
        self.connection = connection
        self.key = bytes(key)
        self.session_id = session_id
        self.local_role = local_role
        self.remote_role = "guest" if local_role == "host" else "host"
        self._send_sequence = 0
        self._receive_sequence = 0

    def _mac(self, value: dict[str, Any]) -> str:
        return hmac.new(self.key, canonical_json_bytes(value), hashlib.sha256).hexdigest()

    def send(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        request_sha256: str | None = None,
    ) -> None:
        if kind not in ROLE_KINDS[self.local_role] or not isinstance(payload, dict):
            raise AdapterError("channel_message_invalid", "VM channel message is unsupported")
        self._send_sequence += 1
        unsigned = {
            "schema_version": CHANNEL_SCHEMA_VERSION,
            "sender": self.local_role,
            "kind": kind,
            "sequence": self._send_sequence,
            "session_id": self.session_id,
            "request_sha256": request_sha256,
            "payload": payload,
        }
        document = {**unsigned, "mac": self._mac(unsigned)}
        body = canonical_json_bytes(document)
        if len(body) > MAX_CHANNEL_MESSAGE_BYTES:
            raise AdapterError("channel_message_too_large", "VM channel message exceeded its bound")
        self.connection.sendall(struct.pack("!I", len(body)) + body)

    def _read_exact(self, size: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < size:
            block = self.connection.recv(size - len(chunks))
            if not block:
                raise AdapterError("channel_closed", "VM channel closed unexpectedly")
            chunks.extend(block)
        return bytes(chunks)

    def receive(self) -> ChannelMessageV1:
        size = struct.unpack("!I", self._read_exact(4))[0]
        if size <= 0 or size > MAX_CHANNEL_MESSAGE_BYTES:
            raise AdapterError("channel_message_too_large", "VM channel message exceeded its bound")
        try:
            document = json.loads(self._read_exact(size))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AdapterError(
                "channel_message_invalid", "VM channel message is malformed"
            ) from error
        expected = {
            "schema_version",
            "sender",
            "kind",
            "sequence",
            "session_id",
            "request_sha256",
            "payload",
            "mac",
        }
        if not isinstance(document, dict) or set(document) != expected:
            raise AdapterError("channel_message_invalid", "VM channel fields changed")
        mac = document.pop("mac")
        if not isinstance(mac, str) or not hmac.compare_digest(mac, self._mac(document)):
            raise AdapterError("channel_authentication_failed", "VM channel authentication failed")
        if (
            document["schema_version"] != CHANNEL_SCHEMA_VERSION
            or document["sender"] != self.remote_role
            or document["kind"] not in ROLE_KINDS[self.remote_role]
            or document["session_id"] != self.session_id
            or not isinstance(document["payload"], dict)
            or not isinstance(document["sequence"], int)
            or document["sequence"] != self._receive_sequence + 1
        ):
            raise AdapterError("channel_message_invalid", "VM channel message is out of context")
        request_sha256 = document["request_sha256"]
        if request_sha256 is not None and (
            not isinstance(request_sha256, str)
            or len(request_sha256) != 64
            or any(value not in "0123456789abcdef" for value in request_sha256)
        ):
            raise AdapterError("channel_message_invalid", "VM channel request identity is invalid")
        self._receive_sequence = document["sequence"]
        return ChannelMessageV1(
            sender=document["sender"],
            kind=document["kind"],
            sequence=document["sequence"],
            session_id=document["session_id"],
            request_sha256=request_sha256,
            payload=document["payload"],
            mac=mac,
        )
