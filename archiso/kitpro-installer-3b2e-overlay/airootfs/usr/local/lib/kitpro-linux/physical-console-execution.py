#!/usr/bin/env python3
"""One-shot, owner-authorized physical installation service."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import time
from dataclasses import asdict
from pathlib import Path

from kitpro_execution_adapter import (
    AdapterError,
    AuthorizationBindingV1,
    PeerCredentials,
    PhysicalAuthorizationIssuer,
    PhysicalOperatorApprovalGate,
    ProtectedSecretBroker,
    canonical_json_bytes,
    load_private_key_fd,
    serve_once,
)
from tools.install.live_service import build_physical_service

RUN_ROOT = Path("/run/kitpro-installer")
REQUEST_PATH = RUN_ROOT / "ui-request.json"
ENVELOPE_PATH = RUN_ROOT / "authorized-envelope.json"
STATUS_PATH = RUN_ROOT / "authorization-status.json"
SOCKET_PATH = RUN_ROOT / "live-execution.sock"
BOOT_MOUNT = Path("/run/archiso/bootmnt")
KERNEL_COMMAND_LINE = Path("/proc/cmdline")


class PhysicalConsoleApprovalGate(PhysicalOperatorApprovalGate):
    """Keep human confirmation short while the ticket retains the full binding."""

    def phrase(self, binding: AuthorizationBindingV1) -> str:
        binding.validate()
        return "AUTHORIZE"


def sha256_file(path: Path, *, length: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb", buffering=0) as source:
        while remaining is None or remaining > 0:
            read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            block = source.read(read_size)
            if not block:
                break
            digest.update(block)
            if remaining is not None:
                remaining -= len(block)
    if remaining not in {None, 0}:
        raise RuntimeError("installation media ended before its ISO filesystem boundary")
    return digest.hexdigest()


def command(arguments: list[str]) -> str:
    completed = subprocess.run(arguments, text=True, capture_output=True, check=False)
    if completed.returncode:
        operation = Path(arguments[0]).name
        raise RuntimeError(
            f"physical installation-media inspection failed: {operation} returned "
            f"{completed.returncode}"
        )
    return completed.stdout.strip()


def optional_command(arguments: list[str]) -> str | None:
    completed = subprocess.run(arguments, text=True, capture_output=True, check=False)
    return completed.stdout.strip() if completed.returncode == 0 else None


def kernel_parameter(name: str) -> str:
    values = [
        token.split("=", 1)[1]
        for token in shlex.split(KERNEL_COMMAND_LINE.read_text())
        if token.startswith(f"{name}=")
    ]
    if len(values) != 1 or not values[0] or len(values[0]) > 128:
        raise RuntimeError(f"physical boot parameter {name} is missing or ambiguous")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._:" for character in values[0]):
        raise RuntimeError(f"physical boot parameter {name} is invalid")
    return values[0]


def _parent_device(source_path: Path) -> Path:
    source_type = command(["/usr/bin/lsblk", "-dn", "-o", "TYPE", str(source_path)])
    if source_type == "part":
        parent = command(["/usr/bin/lsblk", "-dn", "-o", "PKNAME", str(source_path)])
        if not parent:
            raise RuntimeError("installation-media parent disk is unavailable")
        return (Path("/dev") / parent).resolve(strict=True)
    if source_type in {"disk", "rom"}:
        return source_path.resolve(strict=True)
    raise RuntimeError("installation media has an unsupported device type")


def physical_media_device() -> tuple[Path, frozenset[str], int]:
    source = optional_command(["/usr/bin/findmnt", "-n", "-o", "SOURCE", str(BOOT_MOUNT)])
    sources: set[Path] = set()
    if source:
        filesystem = command(["/usr/bin/findmnt", "-n", "-o", "FSTYPE", str(BOOT_MOUNT)])
        options = set(
            command(["/usr/bin/findmnt", "-n", "-o", "OPTIONS", str(BOOT_MOUNT)]).split(",")
        )
        if not source.startswith("/dev/") or filesystem != "iso9660" or "ro" not in options:
            raise RuntimeError("installation media is not a read-only ISO filesystem")
        sources.add(Path(source).resolve(strict=True))
    else:
        boot_uuid = kernel_parameter("archisosearchuuid")
        discovered = command(
            ["/usr/bin/blkid", "-t", f"UUID={boot_uuid}", "-o", "device"]
        ).splitlines()
        for raw_path in discovered:
            candidate = Path(raw_path).resolve(strict=True)
            filesystem = command(
                ["/usr/bin/blkid", "-p", "-s", "TYPE", "-o", "value", str(candidate)]
            )
            if filesystem == "iso9660":
                sources.add(candidate)
        if not sources:
            raise RuntimeError("physical boot media UUID does not identify an ISO filesystem")

    devices = {_parent_device(source_path) for source_path in sources}
    if len(devices) != 1:
        raise RuntimeError("physical boot media identity is ambiguous")
    device = devices.pop()
    device_type = command(["/usr/bin/lsblk", "-dn", "-o", "TYPE", str(device)])
    if device_type != "rom":
        transport = command(["/usr/bin/lsblk", "-dn", "-o", "TRAN", str(device)])
        removable = command(["/usr/bin/lsblk", "-dn", "-o", "RM", str(device)])
        if transport != "usb" and removable != "1":
            raise RuntimeError("physical boot media is not a removable USB device")
    size_value = command(
        ["/usr/bin/blkid", "-p", "-s", "FSSIZE", "-o", "value", str(device)]
    )
    try:
        iso_size = int(size_value)
    except ValueError as error:
        raise RuntimeError("installation-media ISO boundary is unavailable") from error
    if iso_size <= 0:
        raise RuntimeError("installation-media ISO boundary is invalid")
    # Installation targets are whole disks. Bind the authorization environment
    # to the verified parent USB disk; partition paths are intentionally not
    # included because the fresh safety inventory contains whole disks only.
    protected_paths = frozenset({str(device)})
    return device, protected_paths, iso_size


def reject_virtual_or_ambiguous_boot() -> None:
    if Path("/sys/firmware/qemu_fw_cfg").exists():
        raise RuntimeError("QEMU evidence is present; physical authorization is refused")
    virtualization = "none"
    detector = Path("/usr/bin/systemd-detect-virt")
    if detector.exists():
        completed = subprocess.run(
            [str(detector)], text=True, capture_output=True, check=False
        )
        if completed.returncode not in {0, 1}:
            raise RuntimeError("physical virtualization detection failed")
        virtualization = completed.stdout.strip() or "none"
    if virtualization not in {"", "none"}:
        raise RuntimeError("physical authorization is unavailable in a virtual machine")
    if not Path("/sys/firmware/efi").is_dir():
        raise RuntimeError("physical installation requires UEFI boot")


def physical_media_identity() -> tuple[str, frozenset[str]]:
    device, protected_paths, iso_size = physical_media_device()
    return sha256_file(device, length=iso_size), protected_paths


def wait_for_request(timeout_seconds: int = 600) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if REQUEST_PATH.is_symlink():
            raise RuntimeError("UI execution request is a symlink")
        try:
            value = json.loads(REQUEST_PATH.read_text())
        except FileNotFoundError:
            time.sleep(0.2)
            continue
        if not isinstance(value, dict):
            raise RuntimeError("UI execution request is invalid")
        return value
    raise RuntimeError("timed out waiting for the UI execution request")


def private_create(path: Path, value: dict[str, object]) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError("private workflow output already exists")
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        os.write(descriptor, canonical_json_bytes(value))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_status(status: str, *, code: str | None = None, message: str | None = None) -> None:
    document: dict[str, object] = {"schema_version": 1, "status": status}
    if code:
        document["error_code"] = code
    if message:
        document["error_message"] = " ".join(message.split())[:240]
    temporary = STATUS_PATH.with_name(f".{STATUS_PATH.name}.{os.getpid()}.tmp")
    temporary.unlink(missing_ok=True)
    private_create(temporary, document)
    os.replace(temporary, STATUS_PATH)


def ephemeral_authority() -> tuple[int, bytes, Path]:
    private = RUN_ROOT / f"physical-authority-{os.getpid()}.pem"
    public = RUN_ROOT / f"physical-authority-{os.getpid()}.pub.pem"
    subprocess.run(
        ["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    private.chmod(0o600)
    subprocess.run(
        [
            "/usr/bin/openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)
        ],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    public_key = public.read_bytes()
    public.unlink()
    return load_private_key_fd(private), public_key, private


def main() -> int:
    RUN_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    issuer: PhysicalAuthorizationIssuer | None = None
    try:
        if os.geteuid() != 0:
            raise RuntimeError("physical installation service requires root")
        reject_virtual_or_ambiguous_boot()
        media_sha256, media_paths = physical_media_identity()
        python_sha256 = sha256_file(Path("/usr/bin/python"))
        peer = PeerCredentials(os.getpid(), os.geteuid(), os.getegid(), python_sha256)
        request = wait_for_request()
        write_status("waiting")
        key_fd, public_key, private_path = ephemeral_authority()
        gate = PhysicalConsoleApprovalGate(media_sha256=media_sha256)
        try:
            issuer = PhysicalAuthorizationIssuer(
                private_key_fd=key_fd,
                public_key_pem=public_key,
                approval_gate=gate,
            )
        finally:
            os.close(key_fd)
            private_path.unlink(missing_ok=True)
        try:
            with ProtectedSecretBroker() as broker:
                service = build_physical_service(
                    media_sha256=media_sha256,
                    installation_media_paths=media_paths,
                    authorization_public_key_pem=public_key,
                    expected_client_executable_sha256=python_sha256,
                    broker=broker,
                )
                binding = service.authorization_binding(peer, request)
                planned_target = request.get("plan", {}).get("plan", {}).get("target", {})
                if not isinstance(planned_target, dict):
                    raise RuntimeError("physical installation target is unavailable")
                os.write(
                    1,
                    (
                        "\nKITPro Linux physical installation authorization\n"
                        f"Boot media SHA-256: {media_sha256}\n"
                        f"Target path: {planned_target.get('path')}\n"
                        f"Target capacity: {planned_target.get('size_bytes')} bytes\n"
                        f"Target identity: {planned_target.get('identity')}\n"
                        f"Target identity SHA-256: {binding.target_identity_sha256}\n"
                        "Review the target details in the installer on tty1.\n"
                        "Type the exact authorization phrase shown below to continue.\n"
                    ).encode(),
                )
                subprocess.run(["/usr/bin/chvt", "9"], check=True)
                approval = gate.confirm_console(binding, terminal_fd=0, operator_uid=os.geteuid())
                authorization = issuer.issue(binding, approval, ttl_seconds=300)
                write_status("approved")
                envelope = {
                    "schema_version": 1,
                    "adapter_api_version": 1,
                    "authorization_scope": authorization.scope,
                    "request": request,
                    "authorization": asdict(authorization),
                }
                private_create(ENVELOPE_PATH, envelope)
                issuer.close()
                issuer = None
                subprocess.run(["/usr/bin/chvt", "1"], check=True)
                serve_once(service, SOCKET_PATH)
        finally:
            if issuer is not None:
                issuer.close()
        return 0
    except AdapterError as error:
        write_status(
            "denied" if error.code.startswith("operator_approval") else "failed",
            code=error.code,
            message=str(error),
        )
        raise
    except BaseException as error:
        write_status("failed", code="physical_authorization_failed", message=str(error))
        raise


if __name__ == "__main__":
    raise SystemExit(main())
