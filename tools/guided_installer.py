#!/usr/bin/env python3
"""Serial-safe guided front end for the authoritative KITPro install engine."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, TextIO

from tools import kitpro_repo
from tools.install import INSTALLER_VERSION
from tools.install.disk import DiskState, discover_disk, list_installable_disks
from tools.install.engine import INSTALLATION_ROOT, apply
from tools.install.model import (
    GIB,
    InstallSpec,
    parse_network,
    parse_spec,
    validate_hostname,
    validate_public_key,
    validate_timezone,
    validate_username,
)
from tools.install.plan import build_plan
from tools.install.passwords import validate_plaintext_password
from tools.install.receipt import load_source_metadata


PRODUCT_NAME = "KITPro Linux Server"
PRODUCT_VERSION = "0.8.0-dev.18"
RELEASE_STATUS = "Development"
RELEASE = "0.1-dev"
GENERATION = "0.1-dev-g0010"
DEFAULT_RUNTIME_ROOT = Path("/run/kitpro-installer")
DEFAULT_ZONEINFO_ROOT = Path("/usr/share/zoneinfo")


class GuidedStep(str, Enum):
    WELCOME = "welcome"
    SOURCE = "source"
    DISK = "disk"
    HOSTNAME = "hostname"
    TIMEZONE = "timezone"
    LOCALE = "locale"
    NETWORK = "network"
    ADMINISTRATOR = "administrator"
    SSH = "ssh"
    REVIEW = "review"
    CONFIRM = "confirm"
    INSTALL = "install"
    COMPLETE = "complete"


INSTALL_STEPS = tuple(GuidedStep)


@dataclass(frozen=True)
class GuidedAnswers:
    disk: DiskState
    hostname: str
    timezone: str
    locale: str
    network_mode: str
    address: str | None
    prefix: int | None
    gateway: str | None
    dns: tuple[str, ...]
    administrator: str
    ssh_enabled: bool
    ssh_authorized_keys: tuple[str, ...]


@dataclass(frozen=True)
class MediaIdentity:
    product_name: str = PRODUCT_NAME
    product_version: str = PRODUCT_VERSION
    release_status: str = RELEASE_STATUS
    repository_release: str = RELEASE
    repository_generation: str = GENERATION
    media_build_identity: str = PRODUCT_VERSION

    @classmethod
    def from_source_metadata(cls, source: dict[str, object] | None) -> "MediaIdentity":
        if not source:
            return cls()
        return cls(
            product_name=str(source.get("product_name") or PRODUCT_NAME),
            product_version=str(source.get("product_version") or PRODUCT_VERSION),
            release_status=str(source.get("release_status") or RELEASE_STATUS),
            repository_release=str(source.get("repository_release") or RELEASE),
            repository_generation=str(source.get("repository_generation") or GENERATION),
            media_build_identity=str(
                source.get("media_build_identity")
                or source.get("media_version")
                or PRODUCT_VERSION
            ),
        )

    def title(self) -> str:
        if self.release_status.lower() in {"stable", "final", "release"}:
            return f"{self.product_name} {self.product_version}"
        return f"{self.product_name} {self.product_version} {self.release_status}".strip()


def build_spec_document(
    answers: GuidedAnswers,
    identity: MediaIdentity = MediaIdentity(),
) -> dict[str, object]:
    """Create and validate a normal v1 answer-file document."""
    network: dict[str, object] = {"mode": answers.network_mode}
    if answers.network_mode == "static":
        network.update(
            {
                "address": answers.address,
                "prefix": answers.prefix,
                "gateway": answers.gateway,
                "dns": list(answers.dns),
            }
        )
    document: dict[str, object] = {
        "version": 1,
        "release": {
            "name": identity.repository_release,
            "generation": identity.repository_generation,
        },
        "system": {
            "hostname": answers.hostname,
            "locale": answers.locale,
            "timezone": answers.timezone,
        },
        "disk": {
            "device": answers.disk.path,
            "target_type": answers.disk.target_type,
            "layout": "standard",
            "filesystem": "ext4",
            "minimum_capacity_gib": 6,
        },
        "network": network,
        "administrator": {
            "username": answers.administrator,
            "ssh_authorized_keys": list(answers.ssh_authorized_keys),
        },
        "ssh": {"enabled": answers.ssh_enabled},
        "firewall": {"ssh": answers.ssh_enabled},
        "boot": {"mode": "uefi"},
    }
    parse_spec(document)
    return document


def destructive_confirmation(disk: DiskState) -> str:
    return f"ERASE {disk.path}"


def review_lines(
    spec: InstallSpec,
    disk: DiskState,
    *,
    local_password_enrolled: bool = False,
) -> list[str]:
    network = "DHCP"
    if spec.network.mode == "static":
        network = (
            f"static {spec.network.address}/{spec.network.prefix}, gateway "
            f"{spec.network.gateway}, DNS {', '.join(spec.network.dns)}"
        )
    return [
        f"Release: {spec.release.name} ({spec.release.generation})",
        f"Target: {disk.path} ({disk.size_bytes / GIB:.1f} GiB)",
        "Layout: GPT, 256 MiB EFI System Partition, remaining space ext4 root",
        f"Hostname: {spec.system.hostname}",
        f"Timezone: {spec.system.timezone}",
        f"Locale: {spec.system.locale}",
        f"Networking: {network}",
        f"Administrator: {spec.administrator.username}",
        "Local console: password enrolled"
        if local_password_enrolled
        else "Local console: account remains password-locked",
        f"SSH: {'enabled' if spec.ssh.enabled else 'disabled'}",
        "SSH authentication: public key only; password login disabled; root login disabled",
        f"Firewall: default-deny inbound; SSH rule {'enabled' if spec.firewall.ssh else 'absent'}",
    ]


def _read_partial_states(state_root: Path) -> list[dict[str, object]]:
    states: list[dict[str, object]] = []
    if not state_root.is_dir():
        return states
    for path in sorted(state_root.glob("*.json")):
        try:
            value = kitpro_repo.load_json(path)
        except (OSError, ValueError):
            continue
        if value.get("result") not in {"installed_pending_first_boot", "passed"}:
            states.append(value)
    return states


class Console:
    def __init__(
        self,
        input_fn: Callable[[str], str] = input,
        output: TextIO = sys.stdout,
        secret_fn: Callable[[str], str] = getpass.getpass,
    ) -> None:
        self.input_fn = input_fn
        self.secret_fn = secret_fn
        self.output = output

    def write(self, value: str = "") -> None:
        print(value, file=self.output, flush=True)

    def ask(self, prompt: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        try:
            value = self.input_fn(f"{prompt}{suffix}: ").strip()
        except EOFError as error:
            raise kitpro_repo.PipelineError("installer input ended unexpectedly") from error
        return value or (default or "")

    def yes_no(self, prompt: str, default: bool = False) -> bool:
        marker = "y/N" if not default else "Y/n"
        while True:
            answer = self.ask(f"{prompt} ({marker})").lower()
            if not answer:
                return default
            if answer in {"y", "yes"}:
                return True
            if answer in {"n", "no"}:
                return False
            self.write("Enter yes or no.")

    def secret(self, prompt: str) -> str:
        try:
            return self.secret_fn(f"{prompt}: ")
        except EOFError as error:
            raise kitpro_repo.PipelineError(
                "installer secret input ended unexpectedly"
            ) from error


def _validated(console: Console, prompt: str, validator: Callable[[str], str], default: str) -> str:
    while True:
        value = console.ask(prompt, default)
        try:
            return validator(value)
        except kitpro_repo.PipelineError as error:
            console.write(f"Invalid value: {error}")


def collect_local_password(console: Console) -> str:
    console.write(
        "Set a local-console password for tty login. SSH password authentication "
        "will remain disabled."
    )
    while True:
        first = console.secret("Local-console administrator password")
        try:
            validate_plaintext_password(first)
        except kitpro_repo.PipelineError as error:
            console.write(f"Invalid password: {error}")
            continue
        confirmation = console.secret("Confirm local-console administrator password")
        if first != confirmation:
            console.write("Passwords do not match.")
            continue
        return first


def _select_disk(console: Console, explicit: Path | None) -> DiskState:
    if explicit is not None:
        return discover_disk(explicit, "block", 6 * GIB)
    disks = list_installable_disks()
    if not disks:
        raise kitpro_repo.PipelineError("no disk passed the installation safety policy")
    console.write("Available installation disks:")
    for number, disk in enumerate(disks, 1):
        model = disk.identity.get("model") or "unknown model"
        signatures = ", ".join(
            str(item.get("type", "unknown")) for item in disk.signatures
        ) or "none"
        console.write(
            f"  {number}. {disk.path}  {disk.size_bytes / GIB:.1f} GiB  "
            f"{model}  signatures={signatures}"
        )
    while True:
        selected = console.ask("Select target disk number")
        if selected.isdigit() and 1 <= int(selected) <= len(disks):
            return disks[int(selected) - 1]
        console.write("Select one of the displayed disk numbers.")


def collect_answers(
    console: Console,
    *,
    target: Path | None = None,
    zoneinfo_root: Path = DEFAULT_ZONEINFO_ROOT,
) -> GuidedAnswers:
    disk = _select_disk(console, target)
    console.write(f"Selected {disk.path}; all existing data will be erased.")
    hostname = _validated(console, "Hostname", validate_hostname, "kitpro")
    timezone = _validated(
        console,
        "Timezone (IANA region/city or UTC)",
        lambda value: validate_timezone(value, zoneinfo_root),
        "UTC",
    )
    while True:
        locale = console.ask("Locale (C.UTF-8 or en_US.UTF-8)", "C.UTF-8")
        if locale in {"C.UTF-8", "en_US.UTF-8"}:
            break
        console.write("Only C.UTF-8 and en_US.UTF-8 are supported.")
    while True:
        network_mode = console.ask("Networking mode (dhcp or static)", "dhcp").lower()
        if network_mode not in {"dhcp", "static"}:
            console.write("Choose dhcp or static.")
            continue
        network_value: dict[str, object] = {"mode": network_mode}
        if network_mode == "static":
            network_value["address"] = console.ask("Static IPv4 address")
            prefix_text = console.ask("Prefix length", "24")
            network_value["prefix"] = int(prefix_text) if prefix_text.isdigit() else prefix_text
            network_value["gateway"] = console.ask("IPv4 gateway")
            network_value["dns"] = [
                item.strip()
                for item in console.ask("DNS servers (comma-separated)").split(",")
                if item.strip()
            ]
        try:
            network = parse_network(network_value)
            break
        except kitpro_repo.PipelineError as error:
            console.write(f"Invalid network configuration: {error}")
    administrator = _validated(
        console, "Administrator username", validate_username, "kitpro-admin"
    )
    ssh_enabled = console.yes_no("Enable OpenSSH with public-key authentication?", True)
    keys: tuple[str, ...] = ()
    if ssh_enabled:
        key = _validated(console, "Administrator SSH public key", validate_public_key, "")
        keys = (key,)
    answers = GuidedAnswers(
        disk=disk,
        hostname=hostname,
        timezone=timezone,
        locale=locale,
        network_mode=network_mode,
        address=network.address,
        prefix=network.prefix,
        gateway=network.gateway,
        dns=network.dns,
        administrator=administrator,
        ssh_enabled=ssh_enabled,
        ssh_authorized_keys=keys,
    )
    # The authoritative parser owns cross-field validation, including static
    # IPv4 and SSH/firewall consistency.
    build_spec_document(answers)
    return answers


def run_guided(
    console: Console,
    *,
    runtime_root: Path = DEFAULT_RUNTIME_ROOT,
    target: Path | None = None,
    zoneinfo_root: Path = DEFAULT_ZONEINFO_ROOT,
    source_metadata: Path | None = None,
    spec_only: bool = False,
    state_root: Path = INSTALLATION_ROOT,
) -> dict[str, object]:
    source = load_source_metadata(source_metadata)
    identity = MediaIdentity.from_source_metadata(source)
    console.write(identity.title())
    console.write(
        f"x86_64 | installer {INSTALLER_VERSION} | media {identity.media_build_identity}"
    )
    console.write(
        f"Repository: {identity.repository_release} / {identity.repository_generation}"
    )
    console.write(
        "This guided installer will install KITPro Linux Server to one selected disk."
    )
    console.write(
        "No disk is erased until you review the summary and type the exact ERASE confirmation."
    )
    partial = _read_partial_states(state_root)
    if partial:
        console.write("Detected prior incomplete installation state:")
        for state in partial:
            console.write(
                f"  target={state.get('target')} stage={state.get('stage')} "
                f"error={state.get('error') or 'none recorded'}"
            )
        console.write("Resume is unsupported. Inspect evidence or enter KITPro Rescue.")
        if console.ask("Type CONTINUE to create a fresh plan") != "CONTINUE":
            raise kitpro_repo.PipelineError("installation stopped because partial state exists")
    answers = collect_answers(console, target=target, zoneinfo_root=zoneinfo_root)
    administrator_password = None if spec_only else collect_local_password(console)
    document = build_spec_document(answers, identity)
    spec = parse_spec(document)
    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    spec_path = runtime_root / "install-spec.json"
    kitpro_repo.atomic_write_json(spec_path, document)
    console.write("Review installation specification:")
    for line in review_lines(
        spec,
        answers.disk,
        local_password_enrolled=administrator_password is not None,
    ):
        console.write(f"  {line}")
    result: dict[str, object] = {
        "status": "specification-created",
        "specification": str(spec_path),
        "install_spec_sha256": spec.sha256(),
        "release": identity.repository_release,
        "generation": identity.repository_generation,
    }
    if spec_only:
        console.write(f"Specification saved to {spec_path}")
        return result
    plan = build_plan(spec)
    plan_path = runtime_root / "install-plan.json"
    kitpro_repo.atomic_write_json(plan_path, plan)
    confirmation = destructive_confirmation(answers.disk)
    console.write("WARNING: installation will irreversibly erase the selected disk.")
    if console.ask(f"Type exactly {confirmation!r} to proceed") != confirmation:
        raise kitpro_repo.PipelineError("destructive confirmation did not match")
    last_stage = "planning"
    disk_modified = False

    def progress(stage: str) -> None:
        nonlocal last_stage, disk_modified
        last_stage = stage
        disk_modified |= stage in {"partitioning", "rootfs_deployment", "validation"}
        console.write(f"[{stage}] {stage.replace('_', ' ').title()}")

    try:
        report_path, report = apply(
            spec,
            plan,
            True,
            source,
            progress,
            administrator_password,
        )
    except Exception as error:
        console.write(f"Installation failed during {last_stage}: {error}")
        console.write(f"Disk may already be modified: {'yes' if disk_modified else 'no'}")
        console.write(f"The saved plan remains under {runtime_root}; inspect the installation report for logs.")
        raise
    console.write("Installation completed successfully.")
    console.write(f"Target: {answers.disk.path}")
    console.write(f"Hostname: {spec.system.hostname}")
    console.write(f"SSH: {'enabled' if spec.ssh.enabled else 'disabled'}")
    console.write("Remove the installation media and reboot into the installed system.")
    console.write(f"Log in as {spec.administrator.username}.")
    console.write("After login, run 'kitpro-health' to confirm system health.")
    console.write("Install receipt: /var/lib/kitpro-linux/install-receipt.json")
    console.write(
        "Kernel fallback will become available after the first qualified kernel update."
    )
    return {
        **result,
        "status": "installed_pending_first_boot",
        "plan": str(plan_path),
        "plan_sha256": plan["plan_sha256"],
        "report": str(report_path),
        "report_result": report["result"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", type=Path, default=DEFAULT_RUNTIME_ROOT)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--zoneinfo-root", type=Path, default=DEFAULT_ZONEINFO_ROOT)
    parser.add_argument("--source-metadata", type=Path)
    parser.add_argument("--spec-only", action="store_true")
    arguments = parser.parse_args()
    try:
        result = run_guided(
            Console(),
            runtime_root=arguments.runtime_root.resolve(),
            target=arguments.target.resolve() if arguments.target else None,
            zoneinfo_root=arguments.zoneinfo_root.resolve(),
            source_metadata=(
                arguments.source_metadata.resolve() if arguments.source_metadata else None
            ),
            spec_only=arguments.spec_only,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
