"""Strict installation-spec parsing and immutable domain types."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from tools import kitpro_repo
from tools.install import SPEC_VERSION


GIB = 1024**3
ABSOLUTE_MINIMUM_BYTES = 6 * GIB
RECOMMENDED_MINIMUM_BYTES = 12 * GIB
MINIMUM_FREE_RESERVE_BYTES = 2 * GIB
ESP_SIZE_BYTES = 256 * 1024**2
SUPPORTED_LOCALES = {"C.UTF-8", "en_US.UTF-8"}
PUBLIC_KEY_TYPES = {
    "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com",
}


@dataclass(frozen=True)
class ReleaseSpec:
    name: str
    generation: str


@dataclass(frozen=True)
class SystemSpec:
    hostname: str
    locale: str
    timezone: str


@dataclass(frozen=True)
class DiskSpec:
    device: str
    target_type: str
    layout: str
    filesystem: str
    minimum_capacity_bytes: int


@dataclass(frozen=True)
class NetworkSpec:
    mode: str
    address: str | None
    prefix: int | None
    gateway: str | None
    dns: tuple[str, ...]


@dataclass(frozen=True)
class AdministratorSpec:
    username: str
    ssh_authorized_keys: tuple[str, ...]
    password_hash: str | None


@dataclass(frozen=True)
class SSHSpec:
    enabled: bool


@dataclass(frozen=True)
class FirewallSpec:
    ssh: bool


@dataclass(frozen=True)
class BootSpec:
    mode: str


@dataclass(frozen=True)
class InstallSpec:
    version: int
    release: ReleaseSpec
    system: SystemSpec
    disk: DiskSpec
    network: NetworkSpec
    administrator: AdministratorSpec
    ssh: SSHSpec
    firewall: FirewallSpec
    boot: BootSpec

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["network"]["dns"] = list(self.network.dns)
        value["administrator"]["ssh_authorized_keys"] = list(
            self.administrator.ssh_authorized_keys
        )
        if self.administrator.password_hash is None:
            value["administrator"].pop("password_hash")
        return value

    def sha256(self) -> str:
        return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(self.to_dict()))


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise kitpro_repo.PipelineError(f"{field} must be an object")
    return value


def _reject_unknown(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise kitpro_repo.PipelineError(f"{field} contains unsupported fields: {unknown}")


def _required_string(value: dict[str, Any], key: str, field: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result:
        raise kitpro_repo.PipelineError(f"{field}.{key} must be a non-empty string")
    return result


def validate_hostname(value: str) -> str:
    """Validate and return the canonical single-label hostname."""
    if not re.fullmatch(r"(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", value):
        raise kitpro_repo.PipelineError("system.hostname is not a valid single-label hostname")
    return value


def validate_timezone(value: str, zoneinfo_root: Path | None = None) -> str:
    """Validate a safe zoneinfo name and, when requested, its live inventory entry."""
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise kitpro_repo.PipelineError("system.timezone must be a relative zoneinfo name")
    if zoneinfo_root is not None:
        candidate = zoneinfo_root.joinpath(*path.parts)
        if not candidate.is_file():
            raise kitpro_repo.PipelineError(f"system.timezone is unavailable: {value}")
    return value


def validate_username(value: str) -> str:
    """Validate and return the supported administrator account name."""
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", value) or value in {"root", "nobody"}:
        raise kitpro_repo.PipelineError("administrator.username is not supported")
    return value


def validate_public_key(value: str) -> str:
    """Validate one OpenSSH public key without accepting private material."""
    if "PRIVATE KEY" in value or "\n" in value or "\r" in value:
        raise kitpro_repo.PipelineError("administrator SSH keys must contain one public key per entry")
    fields = value.split()
    if len(fields) < 2 or fields[0] not in PUBLIC_KEY_TYPES:
        raise kitpro_repo.PipelineError(f"unsupported administrator SSH public key: {value[:32]}")
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", fields[1]):
        raise kitpro_repo.PipelineError("administrator SSH key payload is not base64")
    return value


def validate_password_hash(value: str) -> str:
    """Accept only a precomputed modern crypt(5) password hash."""
    if not re.fullmatch(r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+", value):
        raise kitpro_repo.PipelineError(
            "administrator.password_hash must be a complete yescrypt hash"
        )
    return value


def parse_network(value: Any) -> NetworkSpec:
    """Parse the shared DHCP/static IPv4 installation policy."""
    network = _mapping(value, "network")
    _reject_unknown(network, {"mode", "address", "prefix", "gateway", "dns"}, "network")
    mode = network.get("mode", "dhcp")
    if mode not in {"dhcp", "static"}:
        raise kitpro_repo.PipelineError(f"unsupported network.mode: {mode}")
    address = network.get("address")
    prefix = network.get("prefix")
    gateway = network.get("gateway")
    dns_value = network.get("dns", [])
    if not isinstance(dns_value, list) or not all(isinstance(item, str) for item in dns_value):
        raise kitpro_repo.PipelineError("network.dns must be an array of IPv4 addresses")
    if mode == "dhcp":
        if any(item is not None for item in (address, prefix, gateway)) or dns_value:
            raise kitpro_repo.PipelineError("DHCP network configuration cannot contain static fields")
    else:
        if not isinstance(address, str) or not isinstance(gateway, str):
            raise kitpro_repo.PipelineError("static networking requires address and gateway")
        if not isinstance(prefix, int) or isinstance(prefix, bool) or not 1 <= prefix <= 32:
            raise kitpro_repo.PipelineError("static network prefix must be between 1 and 32")
        try:
            ipaddress.IPv4Address(address)
            ipaddress.IPv4Address(gateway)
            for resolver in dns_value:
                ipaddress.IPv4Address(resolver)
        except ipaddress.AddressValueError as error:
            raise kitpro_repo.PipelineError(f"invalid static IPv4 configuration: {error}") from error
        if not dns_value:
            raise kitpro_repo.PipelineError("static networking requires at least one DNS server")
    return NetworkSpec(mode, address, prefix, gateway, tuple(dns_value))


def parse_spec(document: Any) -> InstallSpec:
    root = _mapping(document, "installation specification")
    _reject_unknown(
        root,
        {"version", "release", "system", "disk", "network", "administrator", "ssh", "firewall", "boot"},
        "installation specification",
    )
    if root.get("version") != SPEC_VERSION:
        raise kitpro_repo.PipelineError(f"unsupported installation specification version: {root.get('version')}")

    release = _mapping(root.get("release"), "release")
    _reject_unknown(release, {"name", "generation"}, "release")
    release_name = _required_string(release, "name", "release")
    generation = _required_string(release, "generation", "release")
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:-dev)?", release_name):
        raise kitpro_repo.PipelineError("release.name has an unsupported format")
    if not re.fullmatch(re.escape(release_name) + r"-g[0-9]{4}", generation):
        raise kitpro_repo.PipelineError("release.generation does not belong to release.name")

    system = _mapping(root.get("system"), "system")
    _reject_unknown(system, {"hostname", "locale", "timezone"}, "system")
    hostname = _required_string(system, "hostname", "system")
    validate_hostname(hostname)
    locale = system.get("locale", "C.UTF-8")
    if locale not in SUPPORTED_LOCALES:
        raise kitpro_repo.PipelineError(f"unsupported system.locale: {locale}")
    timezone = system.get("timezone", "UTC")
    if not isinstance(timezone, str):
        raise kitpro_repo.PipelineError("system.timezone must be a relative zoneinfo name")
    validate_timezone(timezone)

    disk = _mapping(root.get("disk"), "disk")
    _reject_unknown(
        disk,
        {"device", "target_type", "layout", "filesystem", "minimum_capacity_gib"},
        "disk",
    )
    device = _required_string(disk, "device", "disk")
    if not Path(device).is_absolute():
        raise kitpro_repo.PipelineError("disk.device must be an absolute path")
    target_type = disk.get("target_type", "image")
    if target_type not in {"image", "block"}:
        raise kitpro_repo.PipelineError(f"unsupported disk.target_type: {target_type}")
    layout = disk.get("layout", "standard")
    filesystem = disk.get("filesystem", "ext4")
    if layout != "standard" or filesystem != "ext4":
        raise kitpro_repo.PipelineError("The installer supports only standard GPT and ext4")
    minimum_gib = disk.get("minimum_capacity_gib", ABSOLUTE_MINIMUM_BYTES // GIB)
    if not isinstance(minimum_gib, int) or isinstance(minimum_gib, bool) or minimum_gib < 6:
        raise kitpro_repo.PipelineError("disk.minimum_capacity_gib must be an integer of at least 6")

    network = parse_network(root.get("network", {"mode": "dhcp"}))

    administrator = _mapping(root.get("administrator"), "administrator")
    _reject_unknown(
        administrator,
        {"username", "ssh_authorized_keys", "password_hash"},
        "administrator",
    )
    username = _required_string(administrator, "username", "administrator")
    validate_username(username)
    keys = administrator.get("ssh_authorized_keys", [])
    if not isinstance(keys, list) or not all(isinstance(key, str) for key in keys):
        raise kitpro_repo.PipelineError("administrator.ssh_authorized_keys must be an array")
    for key in keys:
        validate_public_key(key)
    password_hash = administrator.get("password_hash")
    if password_hash is not None:
        if not isinstance(password_hash, str):
            raise kitpro_repo.PipelineError(
                "administrator.password_hash must be a string"
            )
        validate_password_hash(password_hash)

    ssh = _mapping(root.get("ssh", {"enabled": False}), "ssh")
    _reject_unknown(ssh, {"enabled"}, "ssh")
    ssh_enabled = ssh.get("enabled", False)
    if not isinstance(ssh_enabled, bool):
        raise kitpro_repo.PipelineError("ssh.enabled must be a boolean")
    if ssh_enabled and not keys:
        raise kitpro_repo.PipelineError("SSH requires at least one administrator public key")

    firewall = _mapping(root.get("firewall", {}), "firewall")
    _reject_unknown(firewall, {"ssh"}, "firewall")
    firewall_ssh = firewall.get("ssh", ssh_enabled)
    if not isinstance(firewall_ssh, bool) or firewall_ssh != ssh_enabled:
        raise kitpro_repo.PipelineError("firewall.ssh must match ssh.enabled")

    boot = _mapping(root.get("boot", {"mode": "uefi"}), "boot")
    _reject_unknown(boot, {"mode"}, "boot")
    if boot.get("mode", "uefi") != "uefi":
        raise kitpro_repo.PipelineError("The installer supports only UEFI boot")

    return InstallSpec(
        version=SPEC_VERSION,
        release=ReleaseSpec(release_name, generation),
        system=SystemSpec(hostname, locale, timezone),
        disk=DiskSpec(device, target_type, layout, filesystem, minimum_gib * GIB),
        network=network,
        administrator=AdministratorSpec(username, tuple(keys), password_hash),
        ssh=SSHSpec(ssh_enabled),
        firewall=FirewallSpec(firewall_ssh),
        boot=BootSpec("uefi"),
    )


def load_spec(path: Path) -> InstallSpec:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise kitpro_repo.PipelineError(f"cannot read installation specification {path}: {error}") from error
    return parse_spec(document)
