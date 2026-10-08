#!/usr/bin/env python3
"""Stage and build the reproducible Phase 4 developer installation ISO."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from tools import kitpro_phase2, kitpro_repo, state_maintenance
from tools.install.rootfs import (
    BASE_ARTIFACTS,
    KERNEL_RUNTIME,
    KERNEL_STATUS,
    SUPPORT_BUNDLE,
    SUPPORT_BUNDLE_RUNTIME,
    SUPPORT_INSPECTION_MODULES,
    SYSTEM_HEALTH,
    SYSTEM_HEALTH_RUNTIME,
    _copy_base_rootfs,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_ROOT = PROJECT_ROOT / ".state/phase4"
TOOL_ROOT = STATE_ROOT / "archiso-tools"
SOURCE_PROFILE = PROJECT_ROOT / "archiso/kitpro-developer"
RELEASE = "0.1-dev"
GENERATION = "0.1-dev-g0010"
BASE_ROOTFS_GENERATION = "0.1-dev-g0002"
SNAPSHOT_DATE = "2026/09/24"
MEDIA_VERSION = "0.8.0-dev.18"
EXPECTED_ARCHISO = "90-1"

REQUIRED_LIVE_PACKAGES = {"arch-install-scripts", "linux-lts", "python"}
REQUIRED_PROFILE_PATHS = {
    "profiledef.sh",
    "packages.x86_64",
    "airootfs/root/.bash_profile",
    "airootfs/etc/systemd/system/getty@tty1.service.d/autologin.conf",
    "airootfs/usr/local/bin/kitpro-install",
    "airootfs/usr/local/bin/kitpro-installer",
    "airootfs/usr/local/bin/kitpro-rescue",
    "airootfs/usr/local/lib/kitpro-linux/media-acceptance",
    "efiboot/loader/entries/02-kitpro-linux-compatibility.conf",
}
REQUIRED_INSTALL_SCHEMAS = {
    "install-spec-v1.schema.json",
    "install-plan.schema.json",
    "installation-report.schema.json",
    "kernel-state.schema.json",
    "kernel-status.schema.json",
    "kernel-transition-receipt.schema.json",
    "recovery-receipt.schema.json",
    "rescue-health.schema.json",
    "support-bundle-manifest.schema.json",
    "support-bundle-inspection.schema.json",
}

LIVE_RUNTIME_EXECUTABLES = (
    "usr/bin/kitpro-health",
    "usr/bin/kitpro-kernel-status",
    "usr/bin/kitpro-support-bundle",
    "usr/lib/kitpro-linux/kernel-lifecycle",
    "usr/lib/kitpro-linux/system-health",
    "usr/lib/kitpro-linux/support-bundle",
    "opt/kitpro-linux/runtime/kernel-lifecycle",
    "opt/kitpro-linux/runtime/kitpro-health",
    "opt/kitpro-linux/runtime/kitpro-kernel-status",
    "opt/kitpro-linux/runtime/kitpro-support-bundle",
    "opt/kitpro-linux/runtime/support-bundle",
    "opt/kitpro-linux/runtime/system-health",
)

LIVE_WRAPPER_TARGETS = {
    "usr/bin/kitpro-health": "/usr/lib/kitpro-linux/system-health",
    "usr/bin/kitpro-kernel-status": "/usr/lib/kitpro-linux/kernel-lifecycle",
    "usr/bin/kitpro-support-bundle": "/usr/lib/kitpro-linux/support-bundle",
}


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git_source_commit() -> str:
    status = kitpro_repo.run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT).stdout
    if status:
        raise kitpro_repo.PipelineError("refusing to stage media from a dirty working tree")
    commit = kitpro_repo.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise kitpro_repo.PipelineError("cannot resolve the media source commit")
    return commit


def tree_sha256(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            records.append({"path": relative, "type": "symlink", "mode": mode, "target": os.readlink(path)})
        elif path.is_file():
            records.append(
                {"path": relative, "type": "file", "mode": mode, "sha256": kitpro_repo.sha256_file(path)}
            )
        elif path.is_dir():
            records.append({"path": relative, "type": "directory", "mode": mode})
    return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(records))


def validate_profile_inputs(profile: Path, project_root: Path = PROJECT_ROOT) -> None:
    missing = sorted(path for path in REQUIRED_PROFILE_PATHS if not (profile / path).is_file())
    missing.extend(
        f"schemas/{name}"
        for name in sorted(REQUIRED_INSTALL_SCHEMAS)
        if not (project_root / "schemas" / name).is_file()
    )
    if missing:
        raise kitpro_repo.PipelineError(
            f"developer media input is incomplete; missing: {missing}"
        )
    packages = {
        line.strip()
        for line in (profile / "packages.x86_64").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    missing_packages = sorted(REQUIRED_LIVE_PACKAGES - packages)
    if missing_packages:
        raise kitpro_repo.PipelineError(
            f"developer media misses required live packages: {missing_packages}"
        )


def validate_live_operator_tooling(root: Path) -> dict[str, Any]:
    """Validate executable modes and runtime targets in a staged or extracted live root."""
    failures: list[str] = []
    modes: dict[str, str] = {}
    for relative in LIVE_RUNTIME_EXECUTABLES:
        path = root / relative
        if not path.exists() or path.is_symlink() or not path.is_file():
            failures.append(f"{relative}: expected a regular file")
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        modes[relative] = f"{mode:04o}"
        if mode != 0o755:
            failures.append(f"{relative}: expected mode 0755, found {mode:04o}")
    for wrapper, target in LIVE_WRAPPER_TARGETS.items():
        path = root / wrapper
        if path.is_file() and target not in path.read_text():
            failures.append(f"{wrapper}: does not reference canonical target {target}")
    for relative in ("usr/bin/bash", "usr/bin/python"):
        if not (root / relative).exists():
            failures.append(f"{relative}: required interpreter is absent")
    for name in sorted(REQUIRED_INSTALL_SCHEMAS):
        relative = f"opt/kitpro-linux/schemas/{name}"
        path = root / relative
        if not path.is_file() or path.is_symlink():
            failures.append(f"{relative}: required schema is absent or unsafe")
    if failures:
        raise kitpro_repo.PipelineError(
            "live operator tooling validation failed: " + "; ".join(failures)
        )
    return {"status": "passed", "modes": modes, "wrapper_targets": LIVE_WRAPPER_TARGETS}


def bootstrap_tools() -> dict[str, Any]:
    report_path = STATE_ROOT / "artifacts/archiso-tools.json"
    marker = TOOL_ROOT / "usr/bin/mkarchiso"
    if not marker.is_file():
        if TOOL_ROOT.exists():
            raise kitpro_repo.PipelineError(f"refusing to replace incomplete archiso tool root: {TOOL_ROOT}")
        cache = STATE_ROOT / "cache"
        log = STATE_ROOT / "log/archiso-tools-pacman.log"
        config = STATE_ROOT / "archiso-tools-pacman.conf"
        cache.mkdir(parents=True, exist_ok=True)
        log.parent.mkdir(parents=True, exist_ok=True)
        kitpro_repo.render_template(
            PROJECT_ROOT / "config/host-tools-pacman.conf.in",
            config,
            {
                "CACHE_PATH": str(cache.resolve()),
                "ARCH_GPG_PATH": str((PROJECT_ROOT / ".state/ingest/2026-09-24/arch-gnupg").resolve()),
                "LOG_PATH": str(log.resolve()),
                "SNAPSHOT_DATE": SNAPSHOT_DATE,
            },
        )
        TOOL_ROOT.mkdir(parents=True)
        kitpro_phase2.run(
            [
                str(kitpro_phase2.pacstrap_path(PROJECT_ROOT / ".state/phase2")),
                "-N", "-G", "-M", "-C", str(config), str(TOOL_ROOT), "archiso",
            ]
        )
    packages = kitpro_phase2.installed_packages(TOOL_ROOT)
    if packages.get("archiso") != EXPECTED_ARCHISO:
        raise kitpro_repo.PipelineError(
            f"expected archiso {EXPECTED_ARCHISO}, found {packages.get('archiso', 'missing')}"
        )
    report = {
        "schema_version": 1,
        "purpose": "Phase 4 host-only archiso build tools",
        "source": f"Arch Linux Archive {SNAPSHOT_DATE}",
        "archiso_version": packages["archiso"],
        "package_count": len(packages),
        "packages": packages,
        "development_host_only": True,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(report_path, report)
    return report


def _copy_runtime(destination: Path) -> None:
    for name in ("config", "runtime", "schemas", "tools"):
        shutil.copytree(
            PROJECT_ROOT / name,
            destination / name,
            symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    docs = destination / "docs"
    docs.mkdir(parents=True)
    for name in (
        "installation-architecture.md", "installation-specification.md",
        "installation-testing.md", "disk-safety.md", "installation-media.md",
        "recovery-limitations.md", "guided-installer.md", "rescue.md",
        "kernel-status.md",
        "support-bundle.md",
    ):
        shutil.copy2(PROJECT_ROOT / "docs" / name, docs / name)


def _copy_repository(destination: Path, manifest: dict[str, Any]) -> None:
    source_generation = PROJECT_ROOT / "repo/stable" / RELEASE / GENERATION
    target_generation = destination / "stable" / RELEASE / GENERATION
    shutil.copytree(source_generation, target_generation, symlinks=True)
    for digest in sorted(kitpro_repo.manifest_object_hashes(manifest)):
        source = kitpro_repo.object_path(PROJECT_ROOT / "repo", digest)
        target = kitpro_repo.object_path(destination, digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, target)
        except OSError:
            shutil.copy2(source, target)


def _build_configuration(profile_sha256: str, commit: str, manifest: dict[str, Any]) -> dict[str, Any]:
    document = {
        "schema_version": 1,
        "media_version": MEDIA_VERSION,
        "source_git_commit": commit,
        "profile_sha256": profile_sha256,
        "archiso_version": EXPECTED_ARCHISO,
        "arch_snapshot": SNAPSHOT_DATE,
        "release": RELEASE,
        "stable_generation": GENERATION,
        "generation_manifest_sha256": kitpro_repo.sha256_file(
            PROJECT_ROOT / "repo/stable" / RELEASE / GENERATION / "manifest.json"
        ),
        "generation_artifact_set_sha256": kitpro_repo.manifest_artifact_hash(manifest),
        "repository_source_model": "embedded-immutable-generation",
        "live_root_source": "verified-phase3-rootfs-plus-pinned-arch-tool-packages",
        "live_root_base_manifest_sha256": kitpro_repo.sha256_file(
            BASE_ARTIFACTS / "rootfs-manifest.json"
        ),
        "boot_modes": ["uefi.systemd-boot"],
        "architecture": "x86_64",
    }
    document["build_configuration_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(document)
    )
    return document


def stage_profile() -> tuple[Path, dict[str, Any]]:
    validate_profile_inputs(SOURCE_PROFILE)
    commit = _git_source_commit()
    output = STATE_ROOT / "staged" / commit
    if output.exists():
        metadata = kitpro_repo.load_json(output / "airootfs/opt/kitpro-linux/media/build-configuration.json")
        return output, metadata
    manifest_path = PROJECT_ROOT / "repo/stable" / RELEASE / GENERATION / "manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    kitpro_repo.verify_manifest_artifacts(
        manifest,
        PROJECT_ROOT / "repo",
        manifest_path.parent,
        PROJECT_ROOT / ".state/dev-keys",
    )
    profile_sha256 = tree_sha256(SOURCE_PROFILE)
    configuration = _build_configuration(profile_sha256, commit, manifest)
    shutil.copytree(SOURCE_PROFILE, output, symlinks=True)
    cache = STATE_ROOT / "cache"
    log = STATE_ROOT / "log/iso-build-pacman.log"
    kitpro_repo.render_template(
        output / "pacman.conf.in",
        output / "pacman.conf",
        {
            "CACHE_PATH": str(cache.resolve()),
            "ARCH_GPG_PATH": str(
                (PROJECT_ROOT / ".state/ingest/2026-09-24/arch-gnupg").resolve()
            ),
            "LOG_PATH": str(log.resolve()),
            "SNAPSHOT_DATE": SNAPSHOT_DATE,
        },
    )
    (output / "pacman.conf.in").unlink()
    cache.mkdir(parents=True, exist_ok=True)
    log.parent.mkdir(parents=True, exist_ok=True)
    project = output / "airootfs/opt/kitpro-linux"
    project.mkdir(parents=True)
    _copy_runtime(project)
    _copy_repository(project / "repo", manifest)
    key_state = project / ".state/dev-keys"
    (key_state / "public").parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(PROJECT_ROOT / ".state/dev-keys/public", key_state / "public")
    shutil.copy2(PROJECT_ROOT / ".state/dev-keys/keys.json", key_state / "keys.json")
    media = project / "media"
    media.mkdir(parents=True)
    kitpro_repo.atomic_write_json(media / "build-configuration.json", configuration)
    kitpro_repo.atomic_write_json(
        media / "source-metadata.json",
        {
            "kind": "developer-iso",
            "media_version": MEDIA_VERSION,
            "product_name": "KITPro Linux Server",
            "product_version": MEDIA_VERSION,
            "release_status": "Development",
            "repository_release": RELEASE,
            "repository_generation": GENERATION,
            "media_build_identity": MEDIA_VERSION,
            "source_git_commit": commit,
            "profile_sha256": profile_sha256,
            "build_configuration_sha256": configuration["build_configuration_sha256"],
        },
    )
    staged_report = {
        **configuration,
        "staged_profile_sha256": tree_sha256(output),
        "embedded_object_count": len(kitpro_repo.manifest_object_hashes(manifest)),
        "embedded_repository_bytes": sum(
            kitpro_repo.object_path(PROJECT_ROOT / "repo", digest).stat().st_size
            for digest in kitpro_repo.manifest_object_hashes(manifest)
        ),
    }
    kitpro_repo.atomic_write_json(STATE_ROOT / "artifacts/staged-profile.json", staged_report)
    return output, configuration


def _tool_version(command: list[str]) -> str:
    environment = os.environ.copy()
    environment["LD_LIBRARY_PATH"] = str(TOOL_ROOT / "usr/lib")
    completed = subprocess.run(
        command,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return next((line.strip() for line in completed.stdout.splitlines() if line.strip()), "unavailable")


def _overlay_tree(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_symlink():
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(os.readlink(path), target)
        elif path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            if target.is_symlink():
                target.unlink()
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def _prepare_live_root(work: Path, profile: Path) -> dict[str, Any]:
    marker = work / "base._make_packages"
    report_path = work / "live-root-preparation.json"
    if marker.is_file() and report_path.is_file():
        return kitpro_repo.load_json(report_path)
    root = work / "x86_64/airootfs"
    if root.exists():
        raise kitpro_repo.PipelineError(f"refusing to replace partial media live root: {root}")
    base_manifest = kitpro_repo.load_json(BASE_ARTIFACTS / "rootfs-manifest.json")
    if base_manifest.get("stable_generation") != BASE_ROOTFS_GENERATION:
        raise kitpro_repo.PipelineError("Phase 3 rootfs seed does not match the media generation")
    root.mkdir(parents=True)
    _copy_base_rootfs(root)
    pacman_config = profile / "pacman.conf"
    package_names = [
        line.strip()
        for line in (profile / "packages.x86_64").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    empty_hooks = STATE_ROOT / "empty-hooks"
    empty_hooks.mkdir(parents=True, exist_ok=True)
    command = [
        "fakeroot", str(TOOL_ROOT / "usr/bin/pacman"),
        "--root", str(root), "--dbpath", str(root / "var/lib/pacman"),
        "--config", str(pacman_config), "--cachedir", str(STATE_ROOT / "cache"),
        "--hookdir", str(empty_hooks), "-Sy", "--noconfirm", "--noscriptlet",
        *package_names,
    ]
    completed = subprocess.run(
        command, cwd=PROJECT_ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    (STATE_ROOT / "log").mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write(STATE_ROOT / "log/live-root-pacman.log", completed.stdout.encode())
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"live-root package augmentation failed ({completed.returncode}); "
            f"see {STATE_ROOT / 'log/live-root-pacman.log'}"
    )
    _overlay_tree(profile / "airootfs", root)
    # The Phase 3 seed is intentionally stable and can contain older copies of
    # operator tooling. Overlay the exact current sources that the authoritative
    # installed-root path uses so rescue media and the installed system expose
    # the same support-bundle verifier, inspector, and viewer.
    for source, destination, mode in (
        (KERNEL_RUNTIME, root / "usr/lib/kitpro-linux/kernel-lifecycle", 0o755),
        (KERNEL_STATUS, root / "usr/bin/kitpro-kernel-status", 0o755),
        (SYSTEM_HEALTH_RUNTIME, root / "usr/lib/kitpro-linux/system-health", 0o755),
        (SYSTEM_HEALTH, root / "usr/bin/kitpro-health", 0o755),
        (SUPPORT_BUNDLE_RUNTIME, root / "usr/lib/kitpro-linux/support-bundle", 0o755),
        (SUPPORT_BUNDLE, root / "usr/bin/kitpro-support-bundle", 0o755),
    ):
        kitpro_phase2.copy(source, destination, mode)
    inspection_package = root / "usr/lib/kitpro-linux/python/tools"
    for module in SUPPORT_INSPECTION_MODULES:
        kitpro_phase2.copy(module, inspection_package / module.name, 0o644)
    # Ship authoritative public trust material only. Both live entry points run
    # phase4_live.prepare, which creates the generated client database in the
    # ephemeral overlay before any pacman operation.
    (root / "root").chmod(0o700)
    for relative in (
        "usr/local/bin/kitpro-install",
        "usr/local/bin/kitpro-installer",
        "usr/local/bin/kitpro-rescue",
        "usr/local/lib/kitpro-linux/media-acceptance",
    ):
        (root / relative).chmod(0o755)
    mkinitcpio_environment = os.environ.copy()
    # The host's managed TMPDIR path is outside the bubblewrap root. /tmp here
    # belongs to the staged root under .state, so large image work still stays
    # on the capacity-qualified repository filesystem.
    mkinitcpio_environment["TMPDIR"] = "/tmp"
    mkinitcpio = subprocess.run(
        [
            "bwrap", "--unshare-user", "--uid", "0", "--gid", "0",
            "--bind", str(root), "/", "--dev", "/dev", "--proc", "/proc",
            "--ro-bind", "/sys", "/sys", "--tmpfs", "/run",
            "/usr/bin/mkinitcpio", "-P",
        ],
        env=mkinitcpio_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    kitpro_repo.atomic_write(STATE_ROOT / "log/live-root-mkinitcpio.log", mkinitcpio.stdout.encode())
    if mkinitcpio.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"live-root initramfs generation failed ({mkinitcpio.returncode}); "
            f"see {STATE_ROOT / 'log/live-root-mkinitcpio.log'}"
        )
    unreadable: list[str] = []
    for path in root.rglob("*"):
        if path.is_file() and not os.access(path, os.R_OK):
            path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IRUSR)
            unreadable.append(path.relative_to(root).as_posix())
    operator_tooling = validate_live_operator_tooling(root)
    kitpro_phase2.validate_repository_isolation(root / "etc/pacman.conf")
    if "ID=kitpro-linux-installer" not in (root / "etc/os-release").read_text():
        raise kitpro_repo.PipelineError("prepared live root has the wrong operating-system identity")
    for path in (
        root / "boot/vmlinuz-linux-lts",
        root / "boot/initramfs-linux-lts.img",
        root / "usr/bin/python",
        root / "usr/bin/pacstrap",
        root / "usr/bin/kitpro-health",
        root / "usr/bin/kitpro-kernel-status",
        root / "usr/bin/kitpro-support-bundle",
        root / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py",
    ):
        if not path.is_file():
            raise kitpro_repo.PipelineError(f"prepared live root misses required file: {path}")
    packages = kitpro_phase2.installed_packages(root)
    report = {
        "schema_version": 1,
        "source": "verified Phase 3 rootfs plus pinned Arch live-tool packages",
        "base_rootfs_manifest_sha256": kitpro_repo.sha256_file(
            BASE_ARTIFACTS / "rootfs-manifest.json"
        ),
        "stable_generation": GENERATION,
        "package_count": len(packages),
        "packages": packages,
        "kernel_sha256": kitpro_repo.sha256_file(root / "boot/vmlinuz-linux-lts"),
        "initramfs_sha256": kitpro_repo.sha256_file(root / "boot/initramfs-linux-lts.img"),
        "operator_tooling": {
            "kitpro_health_sha256": kitpro_repo.sha256_file(root / "usr/bin/kitpro-health"),
            "kitpro_kernel_status_sha256": kitpro_repo.sha256_file(root / "usr/bin/kitpro-kernel-status"),
            "kitpro_support_bundle_sha256": kitpro_repo.sha256_file(root / "usr/bin/kitpro-support-bundle"),
            "support_bundle_runtime_sha256": kitpro_repo.sha256_file(
                root / "usr/lib/kitpro-linux/support-bundle"
            ),
            "support_bundle_inspector_sha256": kitpro_repo.sha256_file(
                root / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py"
            ),
            "validation": operator_tooling,
        },
        "normalized_read_modes": unreadable,
    }
    kitpro_repo.atomic_write_json(report_path, report)
    marker.touch()
    (work / "base._make_custom_airootfs").touch()
    return report


def _prepare_unshare_wrapper() -> Path:
    wrapper = STATE_ROOT / "wrappers/unshare"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write(
        wrapper,
        b"#!/usr/bin/bash\n"
        b"set -euo pipefail\n"
        b"arguments=()\n"
        b"for argument in \"$@\"; do\n"
        b"  [[ $argument == --map-auto ]] || arguments+=(\"$argument\")\n"
        b"done\n"
        b"exec /usr/bin/unshare \"${arguments[@]}\"\n",
        0o755,
    )
    return wrapper.parent


def run_mkarchiso(command: list[str], environment: dict[str, str], state_root: Path = STATE_ROOT) -> None:
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (state_root / "log").mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write(state_root / "log/mkarchiso.log", completed.stdout.encode())
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"mkarchiso failed ({completed.returncode}); see {state_root / 'log/mkarchiso.log'}"
        )


def validate_build_report(report: dict[str, Any]) -> None:
    required = {
        "schema_version", "status", "media_version", "source_git_commit", "profile_sha256",
        "build_configuration_sha256", "stable_generation", "repository_source_model",
        "boot_modes", "archiso_version", "source_date_epoch", "iso_path", "iso_size_bytes",
        "iso_sha256", "built_at", "tool_versions", "live_root",
    }
    missing = sorted(required - set(report))
    if missing:
        raise kitpro_repo.PipelineError(f"media build report misses fields: {missing}")
    if report["schema_version"] != 1 or report["status"] != "passed":
        raise kitpro_repo.PipelineError("media build report did not pass")
    for field in ("profile_sha256", "build_configuration_sha256", "iso_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(report[field])):
            raise kitpro_repo.PipelineError(f"media build report has invalid hash: {field}")
    if report["boot_modes"] != ["uefi.systemd-boot"]:
        raise kitpro_repo.PipelineError("media build report contains an unsupported boot mode")


def build_iso(*, keep_artifacts: bool = False) -> dict[str, Any]:
    state_maintenance.prepare_heavy_work(STATE_ROOT)
    tools = bootstrap_tools()
    profile, configuration = stage_profile()
    commit = configuration["source_git_commit"]
    work = STATE_ROOT / "work" / commit
    output = STATE_ROOT / "out" / commit
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    iso = output / f"kitpro-linux-server-{MEDIA_VERSION}-x86_64.iso"
    report_path = output / "media-build-report.json"
    if iso.is_file() and report_path.is_file():
        report = kitpro_repo.load_json(report_path)
        validate_build_report(report)
        if report["iso_sha256"] == kitpro_repo.sha256_file(iso):
            state_maintenance.cleanup_generated_tree(
                work,
                allowed_root=STATE_ROOT / "work",
                keep_artifacts=keep_artifacts,
            )
            state_maintenance.cleanup_generated_tree(
                profile,
                allowed_root=STATE_ROOT / "staged",
                keep_artifacts=keep_artifacts,
            )
            return report
        raise kitpro_repo.PipelineError("existing ISO does not match its build report")
    source_epoch = kitpro_repo.load_json(
        PROJECT_ROOT / "repo/stable" / RELEASE / GENERATION / "manifest.json"
    )["source_epoch"]
    live_root = _prepare_live_root(work, profile)
    wrapper_path = _prepare_unshare_wrapper()
    command = [
        str(TOOL_ROOT / "usr/bin/mkarchiso"), "-v", "-w", str(work),
        "-o", str(output), str(profile),
    ]
    environment = os.environ.copy()
    environment["PATH"] = (
        f"{wrapper_path}:{TOOL_ROOT / 'usr/bin'}:{environment['PATH']}"
    )
    environment["LD_LIBRARY_PATH"] = str(TOOL_ROOT / "usr/lib")
    environment["SOURCE_DATE_EPOCH"] = str(source_epoch)
    run_mkarchiso(command, environment)
    if not iso.is_file():
        raise kitpro_repo.PipelineError(f"mkarchiso did not create the expected ISO: {iso}")
    report = {
        "schema_version": 1,
        "status": "passed",
        "media_version": MEDIA_VERSION,
        "source_git_commit": commit,
        "profile_sha256": configuration["profile_sha256"],
        "build_configuration_sha256": configuration["build_configuration_sha256"],
        "stable_generation": GENERATION,
        "repository_source_model": "embedded-immutable-generation",
        "boot_modes": ["uefi.systemd-boot"],
        "archiso_version": tools["archiso_version"],
        "source_date_epoch": source_epoch,
        "iso_path": str(iso.relative_to(PROJECT_ROOT)),
        "iso_size_bytes": iso.stat().st_size,
        "iso_sha256": kitpro_repo.sha256_file(iso),
        "built_at": _utc_now(),
        "tool_versions": {
            "mkarchiso": _tool_version([str(TOOL_ROOT / "usr/bin/mkarchiso"), "-h"]),
            "xorriso": _tool_version([str(TOOL_ROOT / "usr/bin/xorriso"), "-version"]),
            "mksquashfs": _tool_version([str(TOOL_ROOT / "usr/bin/mksquashfs"), "-version"]),
        },
        "live_root": {
            "source": live_root["source"],
            "package_count": live_root["package_count"],
            "base_rootfs_manifest_sha256": live_root["base_rootfs_manifest_sha256"],
            "kernel_sha256": live_root["kernel_sha256"],
            "initramfs_sha256": live_root["initramfs_sha256"],
        },
    }
    validate_build_report(report)
    kitpro_repo.atomic_write_json(report_path, report)
    kitpro_repo.atomic_write_json(STATE_ROOT / "artifacts/media-build-report.json", report)
    state_maintenance.cleanup_generated_tree(
        work,
        allowed_root=STATE_ROOT / "work",
        keep_artifacts=keep_artifacts,
    )
    state_maintenance.cleanup_generated_tree(
        profile,
        allowed_root=STATE_ROOT / "staged",
        keep_artifacts=keep_artifacts,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("bootstrap-tools", "stage-profile", "build", "validate-report"))
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--keep-artifacts", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.command == "bootstrap-tools":
            result = bootstrap_tools()
        elif arguments.command == "stage-profile":
            state_maintenance.prepare_heavy_work(STATE_ROOT)
            path, configuration = stage_profile()
            result = {"profile": str(path), "configuration": configuration}
        elif arguments.command == "build":
            result = build_iso(keep_artifacts=arguments.keep_artifacts)
        else:
            if arguments.path is None:
                raise kitpro_repo.PipelineError("validate-report requires a report path")
            result = kitpro_repo.load_json(arguments.path)
            validate_build_report(result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
