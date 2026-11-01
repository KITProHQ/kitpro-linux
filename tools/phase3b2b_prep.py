#!/usr/bin/env python3
"""Compose, build, and safely qualify the Phase 3B.2B preparation ISO."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from kitpro_execution_adapter import load_private_key_fd, public_key_id, sign_document
from tools import kitpro_repo, phase4_media, phase5, production_media

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_ROOT = PROJECT_ROOT / ".state/phase3b2b_prep"
OVERLAY = PROJECT_ROOT / "archiso/kitpro-installer-3b2b-prep-overlay"
VM_TOOLS = PROJECT_ROOT / ".state/phase2/vm-tools"
BUILD_TOOLS = PROJECT_ROOT / ".state/install-memory/worker-root"
PRODUCTION_GENERATION = PROJECT_ROOT / ".state/install-memory/production-input/1.0-g0002"
MEDIA_VERSION = "3b2b-prep.1"
PHASE_DISPLAY = "Phase 3B.2B Preparation"
ISO_LABEL = "KITPRO_INSTALLER_3B2B_PREP"
ISO_NAME_PREFIX = "kitpro-installer-dev"
LAUNCHER_NAME = "kitpro-installer-phase3b2b-prep"
QUALIFIER_NAME = "phase3b2b-prep-qualify"
SERVICE_NAME = "kitpro-phase3b2b-prep-qualification.service"
BOOT_ENTRY_NAME = "00-kitpro-installer-phase3b2b-prep.conf"
QUALIFICATION_ARGUMENT = "kitpro.phase3b2b-prep=qualify"
QUALIFICATION_MARKER = "KITPRO_PHASE3B2B_PREP_QUALIFICATION_PASSED"
EXPECTED_ADAPTER = {
    "api_version": 1,
    "source_commit": "ee4413a12715cd707d083198003487ae2557f80c",
    "version": "0.1.0",
}
EXPECTED_PLANNER = {
    "api_version": 1,
    "source_commit": "b1b8596d52941424545ac7576ed4e89b79624741",
    "version": "1.7.0",
}
EXPECTED_INSTALLER: dict[str, Any] | None = None
RUNTIME_LOCK_NAME = "runtime-lock.json"
INSTALLER_DISPLAY_VERSION = "KITPro Installer 1.1 RC1"
MEDIA_RELEASE_STATUS: str | None = None
TEXTUAL_QUALIFICATION_SERVICE = "kitpro-textual-runtime-qualification.service"
SIGNED_HOST_ATTESTATION = False
HOST_ATTESTATION_SCOPE = ""
ENABLE_LIVE_SERVICE = False
BOOT_TIMEOUT_SECONDS = 3
DISK_SIZE_BYTES = 8 * 1024**3
PROPOSED_TARGET_SIZE_BYTES = 12 * 1024**3
PROPOSED_TARGET = STATE_ROOT / "proposed-target/kitpro-phase3b2b-first-install.raw"
PROPOSED_SERIAL = "KITPRO-3B2B-FIRST"


def _utc_id() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")


def configure_phase3b2c() -> None:
    """Select the isolated Phase 3B.2C profile without changing Phase 3B.2B artifacts."""
    global STATE_ROOT, OVERLAY, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global LAUNCHER_NAME, QUALIFIER_NAME, SERVICE_NAME, BOOT_ENTRY_NAME
    global QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER, EXPECTED_ADAPTER
    global SIGNED_HOST_ATTESTATION, HOST_ATTESTATION_SCOPE
    STATE_ROOT = PROJECT_ROOT / ".state/phase3b2c"
    OVERLAY = PROJECT_ROOT / "archiso/kitpro-installer-3b2c-overlay"
    MEDIA_VERSION = "3b2c-gates.1"
    PHASE_DISPLAY = "Phase 3B.2C Gate Qualification"
    ISO_LABEL = "KITPRO_INSTALLER_3B2C"
    LAUNCHER_NAME = "kitpro-installer-phase3b2c"
    QUALIFIER_NAME = "phase3b2c-qualify"
    SERVICE_NAME = "kitpro-phase3b2c-qualification.service"
    BOOT_ENTRY_NAME = "00-kitpro-installer-phase3b2c.conf"
    QUALIFICATION_ARGUMENT = "kitpro.phase3b2c=qualify"
    QUALIFICATION_MARKER = "KITPRO_PHASE3B2C_QUALIFICATION_PASSED"
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "00a69840ab19eba3b320b6d777fc85eefc4f4954",
        "version": "0.2.0",
    }
    SIGNED_HOST_ATTESTATION = True
    HOST_ATTESTATION_SCOPE = "phase3b2c-qualification-only"


def configure_phase3b2d() -> None:
    """Select the isolated Phase 3B.2D profile without changing earlier artifacts."""
    global STATE_ROOT, OVERLAY, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global LAUNCHER_NAME, QUALIFIER_NAME, SERVICE_NAME, BOOT_ENTRY_NAME
    global QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER, EXPECTED_ADAPTER
    global SIGNED_HOST_ATTESTATION, HOST_ATTESTATION_SCOPE
    STATE_ROOT = PROJECT_ROOT / ".state/phase3b2d"
    OVERLAY = PROJECT_ROOT / "archiso/kitpro-installer-3b2d-overlay"
    MEDIA_VERSION = "3b2d-final-readiness.1"
    PHASE_DISPLAY = "Phase 3B.2D Final Readiness"
    ISO_LABEL = "KITPRO_INSTALLER_3B2D"
    LAUNCHER_NAME = "kitpro-installer-phase3b2d"
    QUALIFIER_NAME = "phase3b2d-qualify"
    SERVICE_NAME = "kitpro-phase3b2d-qualification.service"
    BOOT_ENTRY_NAME = "00-kitpro-installer-phase3b2d.conf"
    QUALIFICATION_ARGUMENT = "kitpro.phase3b2d=qualify"
    QUALIFICATION_MARKER = "KITPRO_PHASE3B2D_QUALIFICATION_PASSED"
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "d0dccc33774b0493c786363310ef58e9a38fc381",
        "version": "0.3.0",
    }
    SIGNED_HOST_ATTESTATION = True
    HOST_ATTESTATION_SCOPE = "phase3b2d-qualification-only"


def configure_phase3b2e() -> None:
    """Select the isolated Phase 3B.2E profile without changing earlier artifacts."""
    global STATE_ROOT, OVERLAY, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global LAUNCHER_NAME, QUALIFIER_NAME, SERVICE_NAME, BOOT_ENTRY_NAME
    global QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER, EXPECTED_ADAPTER
    global SIGNED_HOST_ATTESTATION, HOST_ATTESTATION_SCOPE
    STATE_ROOT = PROJECT_ROOT / ".state/phase3b2e"
    OVERLAY = PROJECT_ROOT / "archiso/kitpro-installer-3b2e-overlay"
    MEDIA_VERSION = "3b2e-live-gated.1"
    PHASE_DISPLAY = "Phase 3B.2E VM Live Integration"
    ISO_LABEL = "KITPRO_INSTALLER_3B2E"
    LAUNCHER_NAME = "kitpro-installer-phase3b2e"
    QUALIFIER_NAME = "phase3b2e-qualify"
    SERVICE_NAME = "kitpro-phase3b2e-qualification.service"
    BOOT_ENTRY_NAME = "00-kitpro-installer-phase3b2e.conf"
    QUALIFICATION_ARGUMENT = "kitpro.phase3b2e=qualify"
    QUALIFICATION_MARKER = "KITPRO_PHASE3B2E_QUALIFICATION_PASSED"
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "a48e4786507c359d45f0c9a8368b33991b5c7196",
        "version": "0.4.0",
    }
    SIGNED_HOST_ATTESTATION = True
    HOST_ATTESTATION_SCOPE = "phase3b2e-qualification-only"


def configure_phase3b2f_r1() -> None:
    """Select the isolated packaged-runtime remediation profile."""
    configure_phase3b2e()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL, ENABLE_LIVE_SERVICE
    global BOOT_TIMEOUT_SECONDS
    global EXPECTED_ADAPTER
    STATE_ROOT = PROJECT_ROOT / ".state/phase3b2f-r1"
    MEDIA_VERSION = "3b2f-r1-live-gated.1"
    PHASE_DISPLAY = "Phase 3B.2F-R1 Packaged Runtime Remediation"
    ISO_LABEL = "KITPRO_INSTALLER_3B2F_R1"
    ENABLE_LIVE_SERVICE = True
    BOOT_TIMEOUT_SECONDS = 10
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "9f6b1e25035c9f2be43156d045c64ee9be04c2e1",
        "version": "0.4.1",
    }


def configure_phase3b2g() -> None:
    """Select the isolated operational authorization workflow profile."""
    configure_phase3b2f_r1()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL, BOOT_ENTRY_NAME
    global BOOT_TIMEOUT_SECONDS, EXPECTED_ADAPTER
    STATE_ROOT = PROJECT_ROOT / ".state/phase3b2g"
    MEDIA_VERSION = "3b2g-first-vm-workflow.9"
    PHASE_DISPLAY = "First VM Operational Authorization Workflow"
    ISO_LABEL = "KITPRO_INSTALLER_3B2G"
    BOOT_ENTRY_NAME = "00-kitpro-installer-phase3b2e.conf"
    BOOT_TIMEOUT_SECONDS = 10
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "ff707fc490af9ec2aa68ae1213c7d47deb3a701b",
        "version": "0.5.0",
    }


def configure_installer_next() -> None:
    """Select the standard future Textual installer development profile."""
    configure_phase3b2g()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL, ISO_NAME_PREFIX
    global BOOT_ENTRY_NAME, EXPECTED_ADAPTER
    STATE_ROOT = PROJECT_ROOT / ".state/installer-next"
    MEDIA_VERSION = "installer-1.1.0rc1-integration.1"
    PHASE_DISPLAY = "1.1 RC1 Integration"
    ISO_LABEL = "KITPRO_INSTALLER_11RC1"
    ISO_NAME_PREFIX = "kitpro-linux-server-dev"
    BOOT_ENTRY_NAME = "00-kitpro-installer.conf"
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "1e21a32e2201b3c12d212cbc859d709924967b06",
        "version": "0.5.0",
    }


def configure_storage_safety() -> None:
    """Select the isolated Storage Inventory Safety qualification profile."""
    configure_installer_next()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global EXPECTED_PLANNER, EXPECTED_INSTALLER, RUNTIME_LOCK_NAME
    global INSTALLER_DISPLAY_VERSION, QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER
    STATE_ROOT = PROJECT_ROOT / ".state/storage-safety"
    MEDIA_VERSION = "installer-1.2.0.dev0-storage-safety.1"
    PHASE_DISPLAY = "Storage Inventory Safety Qualification"
    ISO_LABEL = "KITPRO_STORAGE_SAFE"
    EXPECTED_PLANNER = {
        "api_version": 1,
        "source_commit": "1612c5a9acd14ae5677491f6e40b46fbf27cccc9",
        "version": "1.8.0.dev0",
    }
    EXPECTED_INSTALLER = {
        "source_commit": "24c8fb29c08c504228e17eb620163e5369827f9d",
        "version": "1.2.0.dev0",
    }
    RUNTIME_LOCK_NAME = "runtime-lock.storage-safety.json"
    INSTALLER_DISPLAY_VERSION = "KITPro Installer 1.2 Development"
    QUALIFICATION_ARGUMENT = "textual-runtime-qualification=qualify"
    QUALIFICATION_MARKER = "KITPRO_TEXTUAL_RUNTIME_QUALIFICATION_PASSED"


def configure_installer_1_2_rc() -> None:
    """Select the isolated Installer 1.2 release-candidate preparation profile."""
    configure_installer_next()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global EXPECTED_PLANNER, EXPECTED_INSTALLER, RUNTIME_LOCK_NAME
    global INSTALLER_DISPLAY_VERSION, MEDIA_RELEASE_STATUS
    global QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER
    STATE_ROOT = PROJECT_ROOT / ".state/installer-1.2-rc"
    MEDIA_VERSION = "installer-1.2.0rc1-candidate.1"
    PHASE_DISPLAY = "Installer 1.2 RC1 Preparation"
    ISO_LABEL = "KITPRO_INSTALLER_12RC1"
    EXPECTED_PLANNER = {
        "api_version": 1,
        "source_commit": "3d2e364f698e2769349952cd2bccbe5be0beca1b",
        "version": "1.8.0",
    }
    EXPECTED_INSTALLER = {
        "source_commit": "1e36b3f53aa3fb80386019734bd5e702c0067687",
        "version": "1.2.0rc1",
    }
    RUNTIME_LOCK_NAME = "runtime-lock.installer-1.2.0rc1-candidate.json"
    INSTALLER_DISPLAY_VERSION = "KITPro Installer 1.2 RC1"
    MEDIA_RELEASE_STATUS = "Release Candidate Preparation"
    QUALIFICATION_ARGUMENT = "textual-runtime-qualification=qualify"
    QUALIFICATION_MARKER = "KITPRO_TEXTUAL_RUNTIME_QUALIFICATION_PASSED"


def configure_installer_1_2_final() -> None:
    """Select the isolated Installer 1.2.0 final-component qualification profile."""
    configure_installer_next()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global EXPECTED_PLANNER, EXPECTED_INSTALLER, RUNTIME_LOCK_NAME
    global INSTALLER_DISPLAY_VERSION, MEDIA_RELEASE_STATUS
    global QUALIFICATION_ARGUMENT, QUALIFICATION_MARKER
    STATE_ROOT = PROJECT_ROOT / ".state/installer-1.2-final"
    MEDIA_VERSION = "installer-1.2.0-final-candidate.2"
    PHASE_DISPLAY = "Installer 1.2.0 Final Component Qualification"
    ISO_LABEL = "KITPRO_INSTALLER_120"
    EXPECTED_PLANNER = {
        "api_version": 1,
        "source_commit": "3d2e364f698e2769349952cd2bccbe5be0beca1b",
        "version": "1.8.0",
    }
    EXPECTED_INSTALLER = {
        "source_commit": "d176709fd28e23f1bf5031d6f521297c41e6e6eb",
        "version": "1.2.0",
    }
    RUNTIME_LOCK_NAME = "runtime-lock.installer-1.2.0-final-candidate.2.json"
    INSTALLER_DISPLAY_VERSION = "KITPro Installer 1.2"
    MEDIA_RELEASE_STATUS = "Unpublished Final Component Qualification Candidate"
    QUALIFICATION_ARGUMENT = "textual-runtime-qualification=qualify"
    QUALIFICATION_MARKER = "KITPRO_TEXTUAL_RUNTIME_QUALIFICATION_PASSED"


def configure_linux_1_1_installer_1_2() -> None:
    """Select the isolated Linux 1.1 and final Installer 1.2 integration profile."""
    configure_installer_1_2_final()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL
    global EXPECTED_ADAPTER, EXPECTED_INSTALLER, RUNTIME_LOCK_NAME, MEDIA_RELEASE_STATUS
    STATE_ROOT = PROJECT_ROOT / ".state/linux-1.1-installer-1.2-integration"
    MEDIA_VERSION = "linux-1.1-installer-1.2.0-integration-candidate.17"
    PHASE_DISPLAY = "Linux 1.1 and Installer 1.2 Integration Qualification"
    ISO_LABEL = "KITPRO_LINUX_11_I120"
    EXPECTED_ADAPTER = {
        "api_version": 1,
        "source_commit": "a7402fcb8e56aeb8fbefc33542414f297e44d32c",
        "version": "0.5.1",
    }
    EXPECTED_INSTALLER = {
        "source_commit": "776e207fdc84d78b65b8e1e3759b5eb1cf4414af",
        "version": "1.2.0",
    }
    RUNTIME_LOCK_NAME = "runtime-lock.linux-1.1-final-media-candidate.17.json"
    MEDIA_RELEASE_STATUS = "Unsigned Development Integration Candidate"


def configure_linux_1_1_final_media() -> None:
    """Select the production-trust Linux 1.1 release-candidate media profile."""
    configure_linux_1_1_installer_1_2()
    global STATE_ROOT, MEDIA_VERSION, PHASE_DISPLAY, ISO_LABEL, MEDIA_RELEASE_STATUS
    global ISO_NAME_PREFIX
    global EXPECTED_INSTALLER, RUNTIME_LOCK_NAME
    STATE_ROOT = PROJECT_ROOT / ".state/linux-1.1-final-media"
    MEDIA_VERSION = "1.1.0-rc1-candidate.17"
    PHASE_DISPLAY = "KITPro Linux Server 1.1 Final Media Qualification"
    ISO_LABEL = "KITPRO_LINUX_110"
    ISO_NAME_PREFIX = "kitpro-linux-server"
    MEDIA_RELEASE_STATUS = "Production-Trust Release Candidate; Unpublished"
    EXPECTED_INSTALLER = {
        "source_commit": "776e207fdc84d78b65b8e1e3759b5eb1cf4414af",
        "version": "1.2.0",
    }
    RUNTIME_LOCK_NAME = "runtime-lock.linux-1.1-final-media-candidate.17.json"


def _is_textual_development_profile() -> bool:
    return STATE_ROOT.name in {
        "installer-next",
        "storage-safety",
        "installer-1.2-rc",
        "installer-1.2-final",
        "linux-1.1-installer-1.2-integration",
        "linux-1.1-final-media",
    }


def _includes_workflow_probe() -> bool:
    return STATE_ROOT.name == "phase3b2g" or _is_textual_development_profile()


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _pinned_tool_version(command: list[str]) -> str:
    environment = os.environ.copy()
    environment["LD_LIBRARY_PATH"] = str(VM_TOOLS / "usr/lib")
    result = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    line = next((value.strip() for value in result.stdout.splitlines() if value.strip()), "")
    if result.returncode or not line:
        raise kitpro_repo.PipelineError("cannot identify pinned QEMU")
    return line


def _git_commit(root: Path) -> str:
    result = _run(["git", "rev-parse", "HEAD"], cwd=root)
    commit = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise kitpro_repo.PipelineError(f"cannot resolve source commit: {root}")
    return commit


def _require_clean(root: Path) -> None:
    result = _run(["git", "status", "--porcelain"], cwd=root)
    if result.returncode or result.stdout:
        raise kitpro_repo.PipelineError(f"refusing to package a dirty checkout: {root}")


def _require_ancestor(root: Path, ancestor: str, component: str) -> None:
    result = _run(["git", "merge-base", "--is-ancestor", ancestor, "HEAD"], cwd=root)
    if result.returncode:
        raise kitpro_repo.PipelineError(f"{component} source commit is not in checkout history")


def _replace_profile_identity(profile: Path) -> None:
    path = profile / "profiledef.sh"
    text = path.read_text()
    replacements = {
        r'^iso_name="[^"]+"$': f'iso_name="{ISO_NAME_PREFIX}"',
        r'^iso_label="[^"]+"$': f'iso_label="{ISO_LABEL}"',
        r'^iso_application="[^"]+"$': (
            f'iso_application="KITPro Installer {PHASE_DISPLAY} Development Media"'
        ),
        r'^iso_version="[^"]+"$': f'iso_version="{MEDIA_VERSION}"',
    }
    for pattern, replacement in replacements.items():
        text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
        if count != 1:
            raise kitpro_repo.PipelineError(f"profile identity field did not match: {pattern}")
    permission_anchor = "file_permissions=(\n"
    phase3b2b_prep_permissions = (
        f'  ["/usr/local/bin/{LAUNCHER_NAME}"]="0:0:755"\n'
        f'  ["/usr/local/lib/kitpro-linux/{QUALIFIER_NAME}"]="0:0:755"\n'
    )
    if _is_textual_development_profile():
        phase3b2b_prep_permissions += (
            '  ["/usr/local/bin/kitpro-guided-installer"]="0:0:755"\n'
            '  ["/usr/local/lib/kitpro-linux/textual-runtime-qualify"]="0:0:755"\n'
        )
    if HOST_ATTESTATION_SCOPE == "phase3b2e-qualification-only":
        phase3b2b_prep_permissions += (
            '  ["/usr/local/lib/kitpro-linux/phase3b2e-live-client.py"]="0:0:755"\n'
            '  ["/usr/local/lib/kitpro-linux/phase3b2e-live-service.py"]="0:0:755"\n'
            '  ["/usr/local/lib/kitpro-linux/phase3b2f-r1-composition-probe.py"]="0:0:755"\n'
        )
        if _includes_workflow_probe():
            phase3b2b_prep_permissions += (
                '  ["/usr/local/lib/kitpro-linux/phase3b2g-workflow-probe.py"]="0:0:755"\n'
            )
    if permission_anchor not in text:
        raise kitpro_repo.PipelineError("profile file_permissions declaration is missing")
    text = text.replace(
        permission_anchor,
        permission_anchor + phase3b2b_prep_permissions,
        1,
    )
    path.write_text(text)
    (profile / "efiboot/loader/loader.conf").write_text(
        f"default {BOOT_ENTRY_NAME}\ntimeout {BOOT_TIMEOUT_SECONDS}\nconsole-mode auto\n"
    )


def _integrate_default_textual_boot(profile: Path, legacy_launcher: bytes) -> None:
    """Make the normal development boot entry launch the packaged Textual installer."""
    if not _is_textual_development_profile():
        return
    live = profile / "airootfs"
    guided = live / "usr/local/bin/kitpro-guided-installer"
    guided.write_bytes(legacy_launcher)
    guided.chmod(0o755)

    shell = live / "root/.bash_profile"
    text = shell.read_text()
    serial_marker = "   || -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase8-rescue/raw ]];"
    if serial_marker not in text:
        raise kitpro_repo.PipelineError("console dispatcher marker is missing")
    text = text.replace(
        serial_marker,
        "   || -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase8-rescue/raw\n"
        "   || -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/phase3b2e/raw ]];",
        1,
    )
    late_activation_anchor = "\n# Physical media owns tty1."
    if late_activation_anchor not in text:
        raise kitpro_repo.PipelineError("late qualification activation marker is missing")
    text = text.replace(
        late_activation_anchor,
        "\n# The candidate qualification key may appear after the unit's initial\n"
        "# ConditionPathExists check. Serial login is a safe late activation point.\n"
        "if [[ $current_tty == /dev/ttyS0 \\\n"
        "   && -r /sys/firmware/qemu_fw_cfg/by_name/opt/kitpro/"
        "textual-runtime-qualification/raw ]]; then\n"
        "    marker=/run/kitpro-textual-runtime-qualification-triggered\n"
        "    if [[ ! -e $marker ]]; then\n"
        "        touch \"$marker\"\n"
        "        systemctl start --no-block kitpro-textual-runtime-qualification.service\n"
        "    fi\n"
        "fi\n"
        + late_activation_anchor,
        1,
    )
    shell.write_text(text)

    (live / "etc/motd").write_text(
        "KITPro Linux Server Development Media\n\n"
        f"The normal Install entry launches {INSTALLER_DISPLAY_VERSION}. Rescue and the\n"
        "developer shell remain available from the boot menu. The legacy guided\n"
        "installer is available as kitpro-guided-installer for compatibility.\n"
    )

    entries = profile / "efiboot/loader/entries"
    for entry in entries.glob("*.conf"):
        entry.unlink()
    common = (
        "linux    /%INSTALL_DIR%/boot/%ARCH%/vmlinuz-linux-lts\n"
        "initrd   /%INSTALL_DIR%/boot/%ARCH%/initramfs-linux-lts.img\n"
    )
    base_options = (
        "archisobasedir=%INSTALL_DIR% archisosearchuuid=%ARCHISO_UUID% "
        "cow_spacesize=7G console=ttyS0,115200n8 console=tty0 systemd.show_status=yes"
    )
    documents = {
        "00-kitpro-installer.conf": (
            "title    Install KITPro Linux Server (Textual Installer)\n"
            "sort-key 00\n"
            f"{common}"
            f"options  {base_options} kitpro.mode=install kitpro.phase3b2e=live-candidate\n"
        ),
        "01-kitpro-installer-compatibility.conf": (
            "title    Install KITPro Linux Server (Compatibility Graphics)\n"
            "sort-key 01\n"
            f"{common}"
            f"options  {base_options} nomodeset kitpro.graphics=compatibility "
            "kitpro.mode=install kitpro.phase3b2e=live-candidate\n"
        ),
        "02-kitpro-rescue.conf": (
            "title    KITPro Linux Rescue\n"
            "sort-key 02\n"
            f"{common}"
            f"options  {base_options} kitpro.mode=rescue\n"
        ),
        "03-kitpro-shell.conf": (
            "title    Developer Shell\n"
            "sort-key 03\n"
            f"{common}"
            f"options  {base_options} kitpro.mode=shell\n"
        ),
    }
    for name, document in documents.items():
        (entries / name).write_text(document)


def _integrate_runtime(
    profile: Path,
    configuration: dict[str, Any],
    installer_repo: Path,
    wheelhouse: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _require_clean(PROJECT_ROOT)
    _require_clean(installer_repo)
    lock = installer_repo / "packaging" / RUNTIME_LOCK_NAME
    document = kitpro_repo.load_json(lock)
    if document.get("planner") != EXPECTED_PLANNER:
        raise kitpro_repo.PipelineError("runtime lock does not pin the approved planner")
    _require_ancestor(PROJECT_ROOT, document["planner"]["source_commit"], "planner")
    if EXPECTED_INSTALLER is not None and document.get("installer") != EXPECTED_INSTALLER:
        raise kitpro_repo.PipelineError("runtime lock does not pin the approved installer")
    if document.get("execution_adapter") != EXPECTED_ADAPTER:
        raise kitpro_repo.PipelineError("runtime lock does not pin the approved adapter")
    _require_ancestor(installer_repo, document["installer"]["source_commit"], "installer")
    _require_ancestor(PROJECT_ROOT, document["execution_adapter"]["source_commit"], "adapter")
    legacy_launcher = (profile / "airootfs/usr/local/bin/kitpro-installer").read_bytes()
    phase4_media._overlay_tree(OVERLAY, profile)
    _replace_profile_identity(profile)
    _integrate_default_textual_boot(profile, legacy_launcher)
    if ENABLE_LIVE_SERVICE:
        for relative in (
            ".state/production-verification",
            ".state/phase3",
        ):
            state_path = profile / "airootfs/opt/kitpro-linux" / relative
            state_path.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_path.chmod(0o700)
    runtime = profile / "airootfs/opt/kitpro-installer/runtime"
    report_path = profile / "airootfs/opt/kitpro-installer/runtime-bundle.json"
    command = [
        sys.executable,
        str(installer_repo / "tools/runtime_bundle.py"),
        "--lock",
        str(lock),
        "--wheelhouse",
        str(wheelhouse),
        "--unpack",
        str(runtime),
        "--report",
        str(report_path),
        "--verify-imports",
        "--python=/usr/bin/python",
    ]
    result = _run(command, cwd=installer_repo)
    if result.returncode:
        raise kitpro_repo.PipelineError(f"runtime bundle verification failed:\n{result.stdout}")
    runtime_report = kitpro_repo.load_json(report_path)
    shutil.copy2(lock, profile / "airootfs/opt/kitpro-installer/runtime-lock.json")
    target_lvm_packages = _stage_installer_next_lvm_packages(profile, wheelhouse)
    for relative in (
        "airootfs/usr/local/bin/kitpro-installer",
        f"airootfs/usr/local/bin/{LAUNCHER_NAME}",
        f"airootfs/usr/local/lib/kitpro-linux/{QUALIFIER_NAME}",
    ):
        (profile / relative).chmod(0o755)
    wants = profile / "airootfs/etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, exist_ok=True)
    os.symlink(
        f"../{SERVICE_NAME}",
        wants / SERVICE_NAME,
    )
    if _is_textual_development_profile():
        os.symlink(
            f"../{TEXTUAL_QUALIFICATION_SERVICE}",
            wants / TEXTUAL_QUALIFICATION_SERVICE,
        )
    if ENABLE_LIVE_SERVICE:
        os.symlink(
            "../kitpro-phase3b2e-live-execution.service",
            wants / "kitpro-phase3b2e-live-execution.service",
        )
        os.symlink(
            "../kitpro-physical-console-execution.service",
            wants / "kitpro-physical-console-execution.service",
        )
        if _includes_workflow_probe():
            os.symlink(
                "../kitpro-phase3b2g-workflow-probe.service",
                wants / "kitpro-phase3b2g-workflow-probe.service",
            )
        os.symlink(
            "../kitpro-phase3b2f-r1-composition-probe.service",
            wants / "kitpro-phase3b2f-r1-composition-probe.service",
        )
    base_configuration_sha256 = configuration["build_configuration_sha256"]
    configuration = dict(configuration)
    configuration.update(
        media_version=MEDIA_VERSION,
        iso_filename=f"{ISO_NAME_PREFIX}-{MEDIA_VERSION}-x86_64.iso",
        qualification_only=not ENABLE_LIVE_SERVICE,
        execution_modes=(
            [
                "qualification",
                "live-candidate",
                "physical-console",
                "composition-probe",
                *(["authenticated-workflow-probe"] if _includes_workflow_probe() else []),
            ]
            if ENABLE_LIVE_SERVICE
            else ["qualification"]
        ),
        live_candidate_capable=ENABLE_LIVE_SERVICE,
        physical_console_capable=ENABLE_LIVE_SERVICE,
        live_authorization_embedded=False,
        base_build_configuration_sha256=base_configuration_sha256,
        runtime_lock_sha256=kitpro_repo.sha256_file(lock),
        runtime_tree_sha256=runtime_report["runtime_tree_sha256"],
        wheel_count=runtime_report["wheel_count"],
        target_lvm_package_sha256=target_lvm_packages,
    )
    configuration.pop("build_configuration_sha256", None)
    configuration["build_configuration_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(configuration)
    )
    media = profile / "airootfs/opt/kitpro-linux/media"
    kitpro_repo.atomic_write_json(media / "build-configuration.json", configuration)
    metadata_path = media / "source-metadata.json"
    metadata = kitpro_repo.load_json(metadata_path)
    metadata.update(
        kind="developer-iso",
        media_version=MEDIA_VERSION,
        release_status=(
            MEDIA_RELEASE_STATUS
            or (
                "Development"
                if _is_textual_development_profile()
                else f"{PHASE_DISPLAY} Qualification"
            )
        ),
        media_build_identity=MEDIA_VERSION,
        build_configuration_sha256=configuration["build_configuration_sha256"],
    )
    kitpro_repo.atomic_write_json(metadata_path, metadata)
    details = {
        "installer_source_commit": document["installer"]["source_commit"],
        "planner_source_commit": document["planner"]["source_commit"],
        "adapter_source_commit": document["execution_adapter"]["source_commit"],
        "runtime_lock_sha256": kitpro_repo.sha256_file(lock),
        "runtime_tree_sha256": runtime_report["runtime_tree_sha256"],
        "runtime_imports": runtime_report["runtime_imports"],
        "wheel_count": runtime_report["wheel_count"],
        "target_lvm_package_sha256": target_lvm_packages,
    }
    return configuration, details


def _stage_installer_next_lvm_packages(profile: Path, dependency_directory: Path) -> dict[str, str]:
    """Stage the pinned target LVM packages into the profile mkarchiso assembles."""
    if not _is_textual_development_profile():
        return {}
    destination = profile / "airootfs/opt/kitpro-installer/target-packages"
    destination.mkdir(parents=True, exist_ok=False)
    packages = dict(sorted(phase4_media.TARGET_LVM_PACKAGES.items()))
    for filename, expected_sha256 in packages.items():
        source = dependency_directory / filename
        if not source.is_file() or kitpro_repo.sha256_file(source) != expected_sha256:
            raise kitpro_repo.PipelineError(
                f"pinned target LVM package is unavailable or changed: {filename}"
            )
        shutil.copy2(source, destination / filename)
    kitpro_repo.atomic_write_json(
        destination / "manifest.json",
        {
            "schema_version": 1,
            "purpose": "development-profile target LVM2 support",
            "packages": packages,
        },
    )
    return packages


def _stage_linux_1_1_generation(
    profile: Path, configuration: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replace only the disposable profile's target repository with Linux 1.1."""
    if STATE_ROOT.name not in {
        "linux-1.1-installer-1.2-integration",
        "linux-1.1-final-media",
    }:
        return configuration, {}
    source_repo = STATE_ROOT / "repo"
    generation = source_repo / "stable/1.1/1.1-g0001"
    manifest = kitpro_repo.load_json(generation / "manifest.json")
    production_final = STATE_ROOT.name == "linux-1.1-final-media"
    if production_final:
        descriptor = manifest.get("generation_descriptor", {})
        if (
            manifest.get("signing_fingerprints", {}).get("repository")
            != "52BADA3613798054B7E35840DC088D21DA29F538"
            or descriptor.get("member")
            != "kitpro-linux-release-1.1.0-5/kitpro-generation.json"
            or not descriptor.get("value")
        ):
            raise kitpro_repo.PipelineError("Linux 1.1 production generation identity differs")
        from tools.install import production

        production.verify("1.1-g0001", source_repo)
    else:
        kitpro_repo.validate_manifest(manifest)
        if (
            manifest["release"] != "1.1"
            or manifest["generation_id"] != "1.1-g0001"
            or manifest.get("development_release_candidate") is not True
            or manifest["signing"].get("development_only") is not True
        ):
            raise kitpro_repo.PipelineError("Linux 1.1 development generation identity differs")
    if not production_final:
        key_state = PROJECT_ROOT / ".state/dev-keys"
        keys = kitpro_repo.load_json(key_state / "keys.json")
        kitpro_repo.verify_dev_keys(key_state, keys)
        kitpro_repo.verify_manifest_artifacts(manifest, source_repo, generation, key_state)

    live = profile / "airootfs"
    project = live / "opt/kitpro-linux"
    embedded_repo = project / "repo"
    shutil.rmtree(embedded_repo)
    shutil.copytree(source_repo, embedded_repo, symlinks=not production_final)
    for repository in manifest["repositories"]:
        repository_dir = (
            embedded_repo
            / "stable/1.1/1.1-g0001/core/os"
            / repository["architecture"]
        )
        _stage_database_aliases(repository_dir, repository, production_final)
    if not production_final:
        embedded_keys = project / ".state/dev-keys"
        (embedded_keys / "public").mkdir(parents=True)
        shutil.copy2(key_state / "keys.json", embedded_keys / "keys.json")
        for name in ("kitpro-linux.gpg", "kitpro-linux-trusted", "kitpro-linux-revoked"):
            shutil.copy2(key_state / "public" / name, embedded_keys / "public" / name)
        for role in ("package", "repository"):
            kitpro_repo.setup_kitpro_keyring(embedded_keys / role, embedded_keys / "public")

    profile_path = project / "config/install-rootfs-profile.json"
    rootfs_profile = kitpro_repo.load_json(profile_path)
    rootfs_profile.update(
        {
            "release": "1.1",
            "generation": "1.1-g0001",
            "repository_url": "https://repo.kitpro.us/kitpro-linux/stable/1.1/current/core/os/$arch",
            "trust": "production-signed" if production_final else "development",
            "source_epoch": manifest.get("source_epoch", 0),
            "explicit_packages": [
                package["name"]
                for repository in manifest["repositories"]
                for package in repository["packages"]
                if package["explicit"]
            ],
        }
    )
    kitpro_repo.atomic_write_json(profile_path, rootfs_profile)
    shutil.copy2(
        PROJECT_ROOT / "config/rootfs-build-pacman.conf.in",
        project / "config/rootfs-build-pacman.conf.in",
    )
    shutil.copytree(
        PROJECT_ROOT / "config/rootfs",
        project / "config/rootfs",
        dirs_exist_ok=True,
    )

    metadata_path = project / "media/source-metadata.json"
    metadata = kitpro_repo.load_json(metadata_path)
    metadata.update(
        {
            "kind": "production-trust-release-candidate-media" if production_final else "development-integration-media",
            "product_version": "1.1.0" if production_final else "1.1-development",
            "release_status": MEDIA_RELEASE_STATUS,
            "repository_release": "1.1",
            "repository_generation": "1.1-g0001",
            "media_build_identity": MEDIA_VERSION,
        }
    )
    kitpro_repo.atomic_write_json(metadata_path, metadata)
    (live / "etc/os-release").write_text(
        'NAME="KITPro Linux Server"\n'
        f'PRETTY_NAME="KITPro Linux Server 1.1 {"Release Candidate" if production_final else "Development Integration Media"}"\n'
        f'ID=kitpro-linux-installer\nID_LIKE=arch\nVERSION_ID="{"1.1.0" if production_final else "1.1-development"}"\n'
        f'BUILD_ID="{MEDIA_VERSION}"\nHOME_URL="https://kitpro.us/"\n'
    )
    (live / "etc/motd").write_text(
        f"KITPro Linux Server 1.1 {'production-trust release-candidate' if production_final else 'unsigned development integration'} media.\n"
        "Installer 1.2.0; target generation 1.1-g0001.\n"
    )
    details = {
        "target_release": "1.1",
        "target_generation": "1.1-g0001",
        "target_generation_manifest_sha256": kitpro_repo.sha256_file(generation / "manifest.json"),
        "target_artifact_set_sha256": kitpro_repo.manifest_artifact_hash(manifest),
        "target_package_count": sum(len(repository["packages"]) for repository in manifest["repositories"]),
        "development_trust_only": not production_final,
        "production_signed_generation": production_final,
        "production_signature_policy_unchanged": True,
        "optional_console_installed": False,
    }
    updated = dict(configuration)
    updated["integrated_target"] = details
    updated["build_configuration_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(updated)
    )
    kitpro_repo.atomic_write_json(project / "media/build-configuration.json", updated)
    return updated, details


def _stage_database_aliases(
    repository_dir: Path, repository: dict[str, Any], production_final: bool
) -> None:
    """Provide Pacman's stable database names without weakening final-media inputs."""
    aliases = {
        f"{repository['name']}.db": repository["database"]["filename"],
        f"{repository['name']}.db.sig": repository["database"]["signature_filename"],
    }
    for alias_name, canonical_name in aliases.items():
        alias = repository_dir / alias_name
        canonical = repository_dir / canonical_name
        if alias.exists():
            continue
        if production_final:
            shutil.copy2(canonical, alias)
        else:
            os.symlink(canonical_name, alias)


def compose_profile(installer_repo: Path, wheelhouse: Path) -> dict[str, Any]:
    _require_clean(PROJECT_ROOT)
    _require_clean(installer_repo)
    commit = _git_commit(PROJECT_ROOT)
    run = STATE_ROOT / "compose" / commit
    if run.exists():
        raise kitpro_repo.PipelineError(f"refusing to replace composed profile: {run}")
    run.mkdir(parents=True)
    profile, configuration = production_media.stage_qualification_profile(
        PROJECT_ROOT, PRODUCTION_GENERATION, run
    )
    base_profile_sha256 = configuration["profile_sha256"]
    configuration, details = _integrate_runtime(profile, configuration, installer_repo, wheelhouse)
    configuration, target_details = _stage_linux_1_1_generation(profile, configuration)
    report = {
        "schema_version": 1,
        "status": "composed",
        "kitpro_linux_commit": commit,
        **details,
        **target_details,
        "base_profile_sha256": base_profile_sha256,
        "development_profile_sha256": phase4_media.tree_sha256(profile),
        "build_configuration_sha256": configuration["build_configuration_sha256"],
        "profile": str(profile.relative_to(PROJECT_ROOT)),
        "manual_launcher": "/usr/local/bin/kitpro-installer",
        "existing_launchers_preserved": [
            "kitpro-install",
            "kitpro-guided-installer",
            "kitpro-rescue",
        ],
        "automatic_live_install": _is_textual_development_profile(),
    }
    artifact = STATE_ROOT / "artifacts/profile-composition.json"
    kitpro_repo.atomic_write_json(artifact, report)
    return report


def build_iso(installer_repo: Path, wheelhouse: Path) -> dict[str, Any]:
    _require_clean(PROJECT_ROOT)
    _require_clean(installer_repo)
    build_id = _utc_id()
    integration: dict[str, Any] = {}

    def transform(profile: Path, configuration: dict[str, Any]) -> dict[str, Any]:
        updated, details = _integrate_runtime(profile, configuration, installer_repo, wheelhouse)
        updated, target_details = _stage_linux_1_1_generation(profile, updated)
        integration.update(target_details)
        integration.update(details)
        integration["development_profile_sha256"] = phase4_media.tree_sha256(profile)
        return updated

    wrapper = STATE_ROOT / "wrappers/unshare"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write(
        wrapper,
        b"#!/usr/bin/bash\n"
        b"set -euo pipefail\n"
        b"arguments=()\n"
        b"skip_next=false\n"
        b'for argument in "$@"; do\n'
        b"  if [[ $skip_next == true ]]; then skip_next=false; continue; fi\n"
        b"  if [[ $argument == --setgid ]]; then skip_next=true; continue; fi\n"
        b'  [[ $argument == --map-auto ]] || arguments+=("$argument")\n'
        b"done\n"
        b'exec /usr/bin/unshare "${arguments[@]}"\n',
        0o755,
    )
    tool_bin = BUILD_TOOLS / "usr/bin"
    tool_lib = BUILD_TOOLS / "usr/lib"
    os.environ["PATH"] = f"{wrapper.parent}:{tool_bin}:{os.environ['PATH']}"
    inherited_library_path = os.environ.get("LD_LIBRARY_PATH")
    os.environ["LD_LIBRARY_PATH"] = (
        f"{tool_lib}:{inherited_library_path}" if inherited_library_path else str(tool_lib)
    )
    manifest = phase5.build(
        PROJECT_ROOT,
        PRODUCTION_GENERATION,
        STATE_ROOT / "media",
        build_id,
        keep_artifacts=True,
        production_qualification=True,
        profile_transform=transform,
        worker_tool_root=BUILD_TOOLS,
    )
    iso = Path(manifest["iso_path"])
    report = {
        "schema_version": 1,
        **integration,
        "status": "built",
        "kitpro_linux_commit": _git_commit(PROJECT_ROOT),
        "iso_path": str(iso.relative_to(PROJECT_ROOT)),
        "iso_size_bytes": iso.stat().st_size,
        "iso_sha256": kitpro_repo.sha256_file(iso),
        "stable_generation": manifest["stable_generation"],
        "generation_manifest_sha256": manifest["generation_manifest_sha256"],
        "build_manifest": str(
            (STATE_ROOT / "media/runs" / build_id / "build-manifest.json").relative_to(PROJECT_ROOT)
        ),
        "qemu_qualification_required": True,
    }
    kitpro_repo.atomic_write_json(STATE_ROOT / "artifacts/development-iso.json", report)
    return report


def _qemu_command(
    run: Path,
    iso: Path,
    disk: Path,
    acceleration: str,
    owner_sha256: str,
    vm_identity_sha256: str,
) -> list[str]:
    if HOST_ATTESTATION_SCOPE == "phase3b2e-qualification-only":
        firmware = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
        guest_run = "/work"
        guest_iso = f"/mnt/{iso.name}"
        command = [
            "/usr/bin/qemu-system-x86_64",
            "-machine",
            f"q35,accel={acceleration}",
            "-cpu",
            "host" if acceleration == "kvm" else "max",
            "-m",
            "8192",
            "-smp",
            "2",
            "-drive",
            f"if=pflash,format=raw,readonly=on,file={firmware}",
            "-drive",
            f"if=pflash,format=raw,file={guest_run}/OVMF_VARS.4m.fd",
            "-drive",
            f"if=none,format=raw,readonly=on,file={guest_run}/target.raw,id=target",
            "-device",
            "virtio-blk-pci,drive=target,serial=KITPRO-PREP-READONLY",
            "-drive",
            f"file={guest_iso},media=cdrom,readonly=on",
            "-boot",
            "order=d,menu=off,strict=on",
            "-fw_cfg",
            f"name=opt/kitpro/{QUALIFICATION_ARGUMENT.split('=')[0]},string=1",
            "-fw_cfg",
            f"name=opt/kitpro/iso-sha256,string={kitpro_repo.sha256_file(iso)}",
            "-fw_cfg",
            f"name=opt/kitpro/target-owner-sha256,string={owner_sha256}",
            "-fw_cfg",
            f"name=opt/kitpro/vm-identity-sha256,string={vm_identity_sha256}",
            "-netdev",
            "user,id=net0",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-display",
            "none",
            "-serial",
            f"file:{guest_run}/serial.log",
            "-monitor",
            "none",
            "-no-reboot",
        ]
        if (run / "host-target-attestation.json").is_file():
            command.extend(
                [
                    "-fw_cfg",
                    (
                        "name=opt/kitpro/host-target-attestation,"
                        f"file={guest_run}/host-target-attestation.json"
                    ),
                ]
            )
        sandbox = [
            "bwrap",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--ro-bind",
            str(VM_TOOLS),
            "/",
            "--dev",
            "/dev",
        ]
        if acceleration == "kvm":
            sandbox.extend(["--dev-bind", "/dev/kvm", "/dev/kvm"])
        return [
            *sandbox,
            "--proc",
            "/proc",
            "--ro-bind",
            "/sys",
            "/sys",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/run",
            "--ro-bind",
            str(iso.parent),
            "/mnt",
            "--bind",
            str(run),
            guest_run,
            "--chdir",
            guest_run,
            *command,
        ]
    relative = lambda path: "/work/" + str(path.relative_to(PROJECT_ROOT))
    firmware = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
    command = [
        "/usr/bin/qemu-system-x86_64",
        "-machine",
        f"q35,accel={acceleration}",
        "-cpu",
        "host" if acceleration == "kvm" else "max",
        "-m",
        "8192",
        "-smp",
        "2",
        "-drive",
        f"if=pflash,format=raw,readonly=on,file={firmware}",
        "-drive",
        f"if=pflash,format=raw,file={relative(run / 'OVMF_VARS.4m.fd')}",
        "-drive",
        f"if=none,format=raw,readonly=on,file={relative(disk)},id=target",
        "-device",
        "virtio-blk-pci,drive=target,serial=KITPRO-PREP-READONLY",
        "-drive",
        f"file={relative(iso)},media=cdrom,readonly=on",
        "-boot",
        "order=d,menu=off,strict=on",
        "-fw_cfg",
        f"name=opt/kitpro/{QUALIFICATION_ARGUMENT.split('=')[0]},string=1",
        "-fw_cfg",
        f"name=opt/kitpro/iso-sha256,string={kitpro_repo.sha256_file(iso)}",
        "-fw_cfg",
        f"name=opt/kitpro/target-owner-sha256,string={owner_sha256}",
        "-fw_cfg",
        f"name=opt/kitpro/vm-identity-sha256,string={vm_identity_sha256}",
        "-netdev",
        "user,id=net0",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-display",
        "none",
        "-serial",
        f"file:{relative(run / 'serial.log')}",
        "-monitor",
        "none",
        "-no-reboot",
    ]
    attestation = run / "host-target-attestation.json"
    if attestation.is_file():
        command.extend(
            [
                "-fw_cfg",
                f"name=opt/kitpro/host-target-attestation,file={relative(attestation)}",
            ]
        )
    return [
        "bwrap",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--ro-bind",
        str(VM_TOOLS),
        "/",
        "--dev-bind",
        "/dev",
        "/dev",
        "--proc",
        "/proc",
        "--ro-bind",
        "/sys",
        "/sys",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--bind",
        str(PROJECT_ROOT),
        "/work",
        "--chdir",
        "/work",
        *command,
    ]


def qualify_qemu(timeout: int, acceleration: str) -> dict[str, Any]:
    build = kitpro_repo.load_json(STATE_ROOT / "artifacts/development-iso.json")
    iso = PROJECT_ROOT / build["iso_path"]
    if kitpro_repo.sha256_file(iso) != build["iso_sha256"]:
        raise kitpro_repo.PipelineError("development ISO identity changed")
    run = STATE_ROOT / "qemu" / _utc_id()
    run.mkdir(parents=True)
    disk = run / "target.raw"
    with disk.open("xb") as handle:
        handle.truncate(DISK_SIZE_BYTES)
    owner = {
        "schema_version": 1,
        "purpose": "phase3b2b_prep-read-only-qemu-target",
        "ownership_id": str(uuid.uuid4()),
        "path": str(disk.relative_to(PROJECT_ROOT)),
        "size_bytes": DISK_SIZE_BYTES,
        "writable_guest_attachment": False,
        "virtual_serial": "KITPRO-PREP-READONLY",
    }
    kitpro_repo.atomic_write_json(run / "target.raw.owner.json", owner)
    before = kitpro_repo.sha256_file(disk)
    firmware_vars = VM_TOOLS / "usr/share/edk2/x64/OVMF_VARS.4m.fd"
    firmware_code = VM_TOOLS / "usr/share/edk2/x64/OVMF_CODE.4m.fd"
    qemu = VM_TOOLS / "usr/bin/qemu-system-x86_64"
    if not all(path.is_file() for path in (firmware_vars, firmware_code, qemu)):
        raise kitpro_repo.PipelineError("pinned QEMU/OVMF tool root is incomplete")
    shutil.copy2(firmware_vars, run / "OVMF_VARS.4m.fd")
    (run / "serial.log").write_bytes(b"")
    owner_sha256 = kitpro_repo.sha256_file(run / "target.raw.owner.json")
    vm_identity_sha256 = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(
            {
                "acceleration": acceleration,
                "firmware_code_sha256": kitpro_repo.sha256_file(firmware_code),
                "iso_sha256": build["iso_sha256"],
                "ownership_id": owner["ownership_id"],
                "virtual_serial": owner["virtual_serial"],
            }
        )
    )
    if SIGNED_HOST_ATTESTATION:
        environment = {
            "iso_sha256": build["iso_sha256"],
            "qemu_sha256": kitpro_repo.sha256_file(qemu),
            "ovmf_code_sha256": kitpro_repo.sha256_file(firmware_code),
            "ovmf_vars_sha256": kitpro_repo.sha256_file(firmware_vars),
        }
        unsigned_attestation = {
            "schema_version": 1,
            "scope": HOST_ATTESTATION_SCOPE,
            "authority_role": "qualification-host-attestation",
            "issuer_key_id": public_key_id(
                (
                    PROJECT_ROOT
                    / "archiso/kitpro-installer-3b2e-overlay/airootfs/etc/kitpro/qualification-authority.pub.pem"
                ).read_bytes()
            ),
            "target": {
                "canonical_path": str(disk.resolve()),
                "ownership_id": owner["ownership_id"],
                "marker_sha256": owner_sha256,
                "initial_sha256": before,
                "size_bytes": DISK_SIZE_BYTES,
                "virtual_serial": owner["virtual_serial"],
            },
            "environment": environment,
            "guest_target": {
                "path": "/dev/vda",
                "size_bytes": DISK_SIZE_BYTES,
                "virtual_serial": owner["virtual_serial"],
            },
            "guest_disk_inventory": [
                {
                    "path": "/dev/vda",
                    "size_bytes": DISK_SIZE_BYTES,
                    "serial": owner["virtual_serial"],
                    "read_only": True,
                }
            ],
            "production_execution_authorized": False,
            "writable_launch_permitted": False,
        }
        private_key = PROJECT_ROOT / ".state/phase3b2c/authority/qualification-authority.pem"
        key_fd = load_private_key_fd(private_key)
        try:
            signature = sign_document(key_fd, unsigned_attestation)
        finally:
            os.close(key_fd)
        kitpro_repo.atomic_write_json(
            run / "host-target-attestation.json",
            {**unsigned_attestation, "signature": signature},
        )
    command = _qemu_command(run, iso, disk, acceleration, owner_sha256, vm_identity_sha256)
    kitpro_repo.atomic_write_json(run / "qemu-command.json", command)
    log = (run / "qemu.log").open("w")
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
    deadline = time.monotonic() + timeout
    serial = ""
    try:
        while time.monotonic() < deadline:
            serial = (run / "serial.log").read_text(errors="replace")
            if QUALIFICATION_MARKER in serial:
                break
            failed_marker = QUALIFICATION_MARKER.replace("PASSED", "FAILED")
            if failed_marker in serial or process.poll() is not None:
                raise kitpro_repo.PipelineError("QEMU qualification failed; inspect serial log")
            time.sleep(2)
        else:
            raise kitpro_repo.PipelineError("QEMU qualification timed out")
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired as error:
            raise kitpro_repo.PipelineError(
                "guest did not complete an orderly shutdown after qualification"
            ) from error
        if process.returncode != 0:
            raise kitpro_repo.PipelineError(
                f"QEMU exited with status {process.returncode} after qualification"
            )
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=30)
        log.close()
    after = kitpro_repo.sha256_file(disk)
    if before != after:
        raise kitpro_repo.PipelineError("read-only QEMU target image changed")
    report = {
        "schema_version": 1,
        "status": "passed",
        "iso_sha256": build["iso_sha256"],
        "acceleration": acceleration,
        "qemu_command_sha256": kitpro_repo.sha256_file(run / "qemu-command.json"),
        "qemu_version": _pinned_tool_version([str(qemu), "--version"]),
        "ovmf_code_sha256": kitpro_repo.sha256_file(firmware_code),
        "ovmf_vars_template_sha256": kitpro_repo.sha256_file(firmware_vars),
        "vm_identity_sha256": vm_identity_sha256,
        "target_owner_sha256": owner_sha256,
        "disk_owner": owner,
        "disk_sha256_before": before,
        "disk_sha256_after": after,
        "disk_unchanged": True,
        "qualification_marker": QUALIFICATION_MARKER,
        "guest_shutdown_clean": True,
        "serial_log_sha256": kitpro_repo.sha256_file(run / "serial.log"),
        "run_directory": str(run.relative_to(PROJECT_ROOT)),
    }
    kitpro_repo.atomic_write_json(run / "qualification.json", report)
    kitpro_repo.atomic_write_json(STATE_ROOT / "artifacts/qemu-qualification.json", report)
    return report


def prepare_target() -> dict[str, Any]:
    """Create one marker-owned sparse target without attaching or opening it for writes later."""
    parent = PROPOSED_TARGET.parent
    parent.mkdir(parents=True, exist_ok=True)
    canonical_parent = parent.resolve(strict=True)
    if canonical_parent != (STATE_ROOT / "proposed-target").resolve(strict=True):
        raise kitpro_repo.PipelineError("proposed target parent escaped the state directory")
    if PROPOSED_TARGET.exists() or PROPOSED_TARGET.is_symlink():
        raise kitpro_repo.PipelineError("refusing to reuse the proposed installation target")
    with PROPOSED_TARGET.open("xb") as handle:
        handle.truncate(PROPOSED_TARGET_SIZE_BYTES)
    canonical = PROPOSED_TARGET.resolve(strict=True)
    stat = canonical.stat()
    if (
        not canonical.is_file()
        or canonical.is_symlink()
        or stat.st_size != PROPOSED_TARGET_SIZE_BYTES
    ):
        raise kitpro_repo.PipelineError("proposed target identity is invalid")
    evidence = {
        "schema_version": 1,
        "purpose": "phase3b2b-first-writable-install-candidate",
        "ownership_id": str(uuid.uuid4()),
        "canonical_path": str(canonical),
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "owner_uid": stat.st_uid,
        "owner_gid": stat.st_gid,
        "size_bytes": stat.st_size,
        "initial_sha256": kitpro_repo.sha256_file(canonical),
        "virtual_serial": PROPOSED_SERIAL,
        "writable_attachment_authorized": False,
        "attached_to_qemu": False,
    }
    marker = parent / "kitpro-phase3b2b-first-install.owner.json"
    if marker.exists() or marker.is_symlink():
        raise kitpro_repo.PipelineError("refusing to replace proposed target ownership evidence")
    kitpro_repo.atomic_write_json(marker, evidence)
    return {
        **evidence,
        "marker_path": str(marker),
        "marker_sha256": kitpro_repo.sha256_file(marker),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("compose", "build", "qemu", "prepare-target"))
    parser.add_argument("--installer-repo", type=Path)
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--acceleration", choices=("tcg", "kvm"), default="tcg")
    parser.add_argument(
        "--phase",
        choices=(
            "3b2b",
            "3b2c",
            "3b2d",
            "3b2e",
            "3b2f-r1",
            "3b2g",
            "installer-next",
            "storage-safety",
            "installer-1.2-rc",
            "installer-1.2-final",
            "linux-1.1-installer-1.2",
            "linux-1.1-final-media",
        ),
        default="3b2b",
    )
    args = parser.parse_args()
    if args.phase == "3b2c":
        configure_phase3b2c()
    elif args.phase == "3b2d":
        configure_phase3b2d()
    elif args.phase == "3b2e":
        configure_phase3b2e()
    elif args.phase == "3b2f-r1":
        configure_phase3b2f_r1()
    elif args.phase == "3b2g":
        configure_phase3b2g()
    elif args.phase == "installer-next":
        configure_installer_next()
    elif args.phase == "storage-safety":
        configure_storage_safety()
    elif args.phase == "installer-1.2-rc":
        configure_installer_1_2_rc()
    elif args.phase == "installer-1.2-final":
        configure_installer_1_2_final()
    elif args.phase == "linux-1.1-installer-1.2":
        configure_linux_1_1_installer_1_2()
    elif args.phase == "linux-1.1-final-media":
        configure_linux_1_1_final_media()
    try:
        if args.command in {"compose", "build"}:
            if args.installer_repo is None or args.wheelhouse is None:
                raise kitpro_repo.PipelineError(
                    "compose/build require installer repo and wheelhouse"
                )
            report = (
                compose_profile(args.installer_repo.resolve(), args.wheelhouse.resolve())
                if args.command == "compose"
                else build_iso(args.installer_repo.resolve(), args.wheelhouse.resolve())
            )
        elif args.command == "qemu":
            report = qualify_qemu(args.timeout, args.acceleration)
        else:
            report = prepare_target()
    except (OSError, ValueError, subprocess.TimeoutExpired, kitpro_repo.PipelineError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
