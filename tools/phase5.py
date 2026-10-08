#!/usr/bin/env python3
"""Create verified Phase 5 inputs, build media, and inspect the result."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from tools import kitpro_repo, phase4_media, state_maintenance, worker_check


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RELEASE = "0.1-dev"
GENERATION = "0.1-dev-g0010"
MEDIA_VERSION = phase4_media.MEDIA_VERSION
EXPECTED_ARCHISO = "90-1"
SQUASHFS_PROCESSORS = 4
ISO_NAME = f"kitpro-linux-server-{MEDIA_VERSION}-x86_64.iso"
SOURCE_PROFILE = PROJECT_ROOT / "archiso/kitpro-developer"
DEFAULT_STATE = PROJECT_ROOT / ".state/phase5"


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _git_state(root: Path) -> tuple[str, bool]:
    commit = kitpro_repo.run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    dirty = bool(kitpro_repo.run(["git", "status", "--porcelain"], cwd=root).stdout)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise kitpro_repo.PipelineError("cannot resolve source Git commit")
    return commit, dirty


def effective_squashfs_options(profiledef: Path) -> list[str]:
    """Evaluate the Archiso profile and return its effective SquashFS options."""
    result = subprocess.run(
        [
            "bash",
            "-c",
            'declare -A file_permissions=(); source "$1"; '
            'printf "%s\\0" "${airootfs_image_tool_options[@]}"',
            "bash",
            str(profiledef),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"cannot evaluate Archiso SquashFS options: {result.stderr.decode(errors='replace').strip()}"
        )
    return [item.decode() for item in result.stdout.split(b"\0") if item]


def validate_squashfs_processor_policy(options: list[str]) -> int:
    positions = [index for index, value in enumerate(options) if value == "-processors"]
    if len(positions) != 1 or positions[0] + 1 >= len(options):
        raise kitpro_repo.PipelineError(
            "Archiso SquashFS options must contain exactly one -processors value"
        )
    try:
        processors = int(options[positions[0] + 1])
    except ValueError as error:
        raise kitpro_repo.PipelineError("Archiso SquashFS processor value is invalid") from error
    if processors != SQUASHFS_PROCESSORS:
        raise kitpro_repo.PipelineError(
            f"Archiso SquashFS processors must be {SQUASHFS_PROCESSORS}, found {processors}"
        )
    return processors


def _squashfs_processors_from_log(log: str) -> list[int]:
    processors = [
        int(value)
        for value in re.findall(r"^Parallel mksquashfs: Using (\d+) processors$", log, re.MULTILINE)
    ]
    if not processors or any(value != SQUASHFS_PROCESSORS for value in processors):
        raise kitpro_repo.PipelineError(
            f"mkarchiso did not confirm {SQUASHFS_PROCESSORS}-processor SquashFS: {processors}"
        )
    return processors


def _cpu_topology() -> dict[str, Any]:
    cpuinfo = Path("/proc/cpuinfo").read_text()
    nproc = subprocess.run(
        ["nproc"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if nproc.returncode != 0 or not nproc.stdout.strip().isdigit():
        raise kitpro_repo.PipelineError("cannot determine worker-visible CPU count")
    cpu_max = Path("/sys/fs/cgroup/cpu.max")
    return {
        "proc_cpuinfo_logical_processors": len(
            re.findall(r"^processor\s*:", cpuinfo, re.MULTILINE)
        ),
        "nproc": int(nproc.stdout.strip()),
        "cgroup_cpu_max": cpu_max.read_text().strip() if cpu_max.is_file() else None,
    }


def _tracked_source_tree_sha256(source_root: Path, relative_root: str) -> str:
    """Hash only Git-tracked source files beneath *relative_root*.

    Validation can create ignored bytecode and cache files in the checkout.
    Those files are not build inputs and must not alter embedded media identity.
    The caller's clean-tree check ensures the tracked working files match the
    selected commit.
    """
    listing = kitpro_repo.run(
        ["git", "ls-files", "-z", "--", relative_root], cwd=source_root
    ).stdout
    paths = sorted(path for path in listing.split("\0") if path)
    if not paths:
        raise kitpro_repo.PipelineError(
            f"tracked source tree is empty: {relative_root}"
        )
    root = source_root / relative_root
    records: list[dict[str, Any]] = []
    for repository_path in paths:
        path = source_root / repository_path
        relative = path.relative_to(root).as_posix()
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            records.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "mode": mode,
                    "target": os.readlink(path),
                }
            )
        elif path.is_file():
            records.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": mode,
                    "sha256": kitpro_repo.sha256_file(path),
                }
            )
        else:
            raise kitpro_repo.PipelineError(
                f"tracked source path has unsupported type: {repository_path}"
            )
    return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(records))


def _inventory(root: Path, *, excluded: set[str] | None = None) -> list[dict[str, Any]]:
    excluded = excluded or set()
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            records.append({"path": relative, "type": "symlink", "mode": mode, "target": os.readlink(path)})
        elif path.is_file():
            records.append({
                "path": relative, "type": "file", "mode": mode,
                "size": path.stat().st_size, "sha256": kitpro_repo.sha256_file(path),
            })
        elif path.is_dir():
            records.append({"path": relative, "type": "directory", "mode": mode})
    return records


def _inventory_hash(records: list[dict[str, Any]]) -> str:
    return kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(records))


def _copy_repository(
    source_repo: Path,
    destination_repo: Path,
    manifest: dict[str, Any],
    generation: str = GENERATION,
) -> None:
    source_generation = source_repo / "stable" / RELEASE / generation
    target_generation = destination_repo / "stable" / RELEASE / generation
    shutil.copytree(source_generation, target_generation, symlinks=True)
    for digest in sorted(kitpro_repo.manifest_object_hashes(manifest)):
        source = kitpro_repo.object_path(source_repo, digest)
        target = kitpro_repo.object_path(destination_repo, digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def create_bundle(
    output: Path,
    repo_root: Path,
    key_state: Path,
    generation: str = GENERATION,
) -> dict[str, Any]:
    if output.exists():
        raise kitpro_repo.PipelineError(f"refusing to replace input bundle: {output}")
    manifest_path = repo_root / "stable" / RELEASE / generation / "manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    if manifest.get("generation_id") != generation:
        raise kitpro_repo.PipelineError("pinned Stable generation identity is wrong")
    kitpro_repo.verify_manifest_artifacts(manifest, repo_root, manifest_path.parent, key_state)
    output.mkdir(parents=True)
    _copy_repository(repo_root, output / "repo", manifest, generation)
    (output / "trust/public").mkdir(parents=True)
    for source in sorted((key_state / "public").iterdir()):
        if source.is_file():
            shutil.copy2(source, output / "trust/public" / source.name)
    shutil.copy2(key_state / "keys.json", output / "trust/keys.json")
    for path in sorted(output.rglob("*"), reverse=True):
        if not path.is_symlink():
            path.chmod(0o555 if path.is_dir() else 0o444)
    inventory = _inventory(output)
    document = {
        "schema_version": 1,
        "kind": "kitpro-phase5-build-input-bundle",
        "release": RELEASE,
        "stable_generation": generation,
        "generation_manifest_sha256": kitpro_repo.sha256_file(
            output / "repo/stable" / RELEASE / generation / "manifest.json"
        ),
        "package_count": sum(len(item["packages"]) for item in manifest["repositories"]),
        "artifact_set_sha256": kitpro_repo.manifest_artifact_hash(manifest),
        "object_count": len(kitpro_repo.manifest_object_hashes(manifest)),
        "contents_inventory_sha256": _inventory_hash(inventory),
        "contents": inventory,
    }
    document["bundle_manifest_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(document)
    )
    kitpro_repo.atomic_write_json(output / "input-bundle.json", document)
    (output / "input-bundle.json").chmod(0o444)
    output.chmod(0o555)
    return document


def _verify_public_signature(gpg_home: Path, signature: Path, artifact: Path) -> str:
    result = subprocess.run(
        ["gpg", "--homedir", str(gpg_home), "--batch", "--status-fd", "1", "--verify",
         str(signature), str(artifact)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        raise kitpro_repo.PipelineError(f"signature validation failed for {artifact.name}: {result.stdout}")
    for line in result.stdout.splitlines():
        match = re.match(r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ", line)
        if match:
            return match.group(1)
    raise kitpro_repo.PipelineError(f"signature result lacks a valid fingerprint: {artifact.name}")


@contextlib.contextmanager
def _verification_gpg_home():
    """Use a short private path so GnuPG agent sockets fit Linux AF_UNIX limits."""
    with tempfile.TemporaryDirectory(prefix="kitpro-gpg-", dir="/tmp") as name:
        home = Path(name)
        home.chmod(0o700)
        if len(os.fsencode(home / "S.gpg-agent")) >= 108:
            raise kitpro_repo.PipelineError("verification GnuPG home is too long for a UNIX socket")
        yield home


def verify_bundle(
    bundle: Path,
    scratch: Path,
    generation: str = GENERATION,
) -> dict[str, Any]:
    document = kitpro_repo.load_json(bundle / "input-bundle.json")
    if document.get("schema_version") != 1 or document.get("stable_generation") != generation:
        raise kitpro_repo.PipelineError("input bundle does not contain the pinned generation")
    expected = dict(document)
    digest = expected.pop("bundle_manifest_sha256", None)
    if digest != kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(expected)):
        raise kitpro_repo.PipelineError("input-bundle manifest hash is invalid")
    actual_inventory = _inventory(bundle, excluded={"input-bundle.json"})
    if actual_inventory != document["contents"] or _inventory_hash(actual_inventory) != document["contents_inventory_sha256"]:
        raise kitpro_repo.PipelineError("input-bundle contents differ from its inventory")
    manifest_path = bundle / "repo/stable" / RELEASE / generation / "manifest.json"
    if kitpro_repo.sha256_file(manifest_path) != document["generation_manifest_sha256"]:
        raise kitpro_repo.PipelineError("generation manifest hash changed in transit")
    manifest = kitpro_repo.load_json(manifest_path)
    kitpro_repo.validate_manifest(manifest)
    if kitpro_repo.manifest_artifact_hash(manifest) != document["artifact_set_sha256"]:
        raise kitpro_repo.PipelineError("generation artifact set changed in transit")
    object_hashes = kitpro_repo.manifest_object_hashes(manifest)
    if len(object_hashes) != document["object_count"]:
        raise kitpro_repo.PipelineError("input bundle object count changed")
    for object_hash in object_hashes:
        path = kitpro_repo.object_path(bundle / "repo", object_hash)
        if not path.is_file() or kitpro_repo.sha256_file(path) != object_hash:
            raise kitpro_repo.PipelineError(f"input bundle object is missing or corrupt: {object_hash}")
    with _verification_gpg_home() as gpg_home:
        kitpro_repo.setup_kitpro_keyring(gpg_home, bundle / "trust/public")
        keys = kitpro_repo.load_json(bundle / "trust/keys.json")
        generation_root = manifest_path.parent
        for repository in manifest["repositories"]:
            repository_root = generation_root / "core/os" / repository["architecture"]
            for package in repository["packages"]:
                signer = _verify_public_signature(
                    gpg_home, repository_root / package["kitpro_signature"]["filename"],
                    repository_root / package["filename"],
                )
                if signer != keys["roles"]["package"]["fingerprint"]:
                    raise kitpro_repo.PipelineError(f"wrong package signer: {package['name']}")
            database = repository["database"]
            signer = _verify_public_signature(
                gpg_home, repository_root / database["signature_filename"],
                repository_root / database["filename"],
            )
            if signer != keys["roles"]["repository"]["fingerprint"]:
                raise kitpro_repo.PipelineError("wrong repository database signer")
    return {
        "status": "passed", "stable_generation": generation,
        "generation_manifest_sha256": document["generation_manifest_sha256"],
        "artifact_set_sha256": document["artifact_set_sha256"],
        "package_count": document["package_count"], "object_count": document["object_count"],
        "bundle_manifest_sha256": document["bundle_manifest_sha256"],
    }


def _copy_runtime(source_root: Path, destination: Path) -> None:
    for name in ("config", "runtime", "schemas", "tools"):
        shutil.copytree(
            source_root / name, destination / name, symlinks=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    (destination / "docs").mkdir(parents=True)
    for name in (
        "installation-architecture.md", "installation-specification.md", "installation-testing.md",
        "disk-safety.md", "installation-media.md", "recovery-limitations.md",
    ):
        shutil.copy2(source_root / "docs" / name, destination / "docs" / name)


def _stage_operator_tooling(source_root: Path, airootfs: Path) -> None:
    files = (
        ("runtime/kernel-lifecycle", "usr/lib/kitpro-linux/kernel-lifecycle", 0o755),
        ("runtime/kitpro-kernel-status", "usr/bin/kitpro-kernel-status", 0o755),
        ("runtime/system-health", "usr/lib/kitpro-linux/system-health", 0o755),
        ("runtime/kitpro-health", "usr/bin/kitpro-health", 0o755),
        ("runtime/support-bundle", "usr/lib/kitpro-linux/support-bundle", 0o755),
        ("runtime/kitpro-support-bundle", "usr/bin/kitpro-support-bundle", 0o755),
        ("runtime/repository-policy.conf", "usr/lib/kitpro-linux/repository-policy.conf", 0o644),
    )
    for source_name, destination_name, mode in files:
        destination = airootfs / destination_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_root / source_name, destination)
        destination.chmod(mode)
    inspection_root = airootfs / "usr/lib/kitpro-linux/python/tools"
    inspection_root.mkdir(parents=True, exist_ok=True)
    for name in ("__init__.py", "system_health.py", "support_bundle.py", "support_bundle_inspect.py"):
        destination = inspection_root / name
        shutil.copy2(source_root / "tools" / name, destination)
        destination.chmod(0o644)


def _build_configuration(source_root: Path, bundle: Path, profile_hash: str, commit: str) -> dict[str, Any]:
    bundle_manifest = kitpro_repo.load_json(bundle / "input-bundle.json")
    squashfs_options = effective_squashfs_options(
        source_root / "archiso/kitpro-developer/profiledef.sh"
    )
    squashfs_processors = validate_squashfs_processor_policy(squashfs_options)
    configuration: dict[str, Any] = {
        "schema_version": 2,
        "media_version": MEDIA_VERSION,
        "source_git_commit": commit,
        "profile_sha256": profile_hash,
        "installation_engine_sha256": _tracked_source_tree_sha256(
            source_root, "tools/install"
        ),
        "install_schema_sha256": kitpro_repo.sha256_file(source_root / "schemas/install-spec-v1.schema.json"),
        "archiso_version": EXPECTED_ARCHISO,
        "arch_snapshot": phase4_media.SNAPSHOT_DATE,
        "release": RELEASE,
        "stable_generation": GENERATION,
        "generation_manifest_sha256": bundle_manifest["generation_manifest_sha256"],
        "generation_artifact_set_sha256": bundle_manifest["artifact_set_sha256"],
        "public_trust_sha256": phase4_media.tree_sha256(bundle / "trust/public"),
        "repository_source_model": "embedded-immutable-generation",
        "live_root_source": "native-mkarchiso-pinned-arch-snapshot",
        "boot_modes": ["uefi.systemd-boot"],
        "architecture": "x86_64",
        "reproducibility_policy": {
            "squashfs_timestamp": "source-date-epoch",
            "squashfs_options": squashfs_options,
            "squashfs_processors": squashfs_processors,
            "efi_fat_creation": "mkfs.fat --invariant",
            "iso_file_dates": "xorriso --set_all_file_dates source-date-epoch",
            "volatile_live_root_paths": [
                "opt/kitpro-linux/.state/client/gnupg",
                "var/cache/ldconfig/aux-cache",
            ],
        },
    }
    configuration["build_configuration_sha256"] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(configuration)
    )
    return configuration


def stage_native_profile(source_root: Path, bundle: Path, run_root: Path) -> tuple[Path, dict[str, Any]]:
    source_profile = source_root / "archiso/kitpro-developer"
    phase4_media.validate_profile_inputs(source_profile, source_root)
    commit, dirty = _git_state(source_root)
    if dirty:
        raise kitpro_repo.PipelineError("refusing release-like Phase 5 build from a dirty source tree")
    verification = verify_bundle(bundle, run_root / "bundle-verification")
    profile_hash = phase4_media.tree_sha256(source_profile)
    configuration = _build_configuration(source_root, bundle, profile_hash, commit)
    profile = run_root / "profile"
    shutil.copytree(source_profile, profile, symlinks=True)
    cache = run_root / "cache"
    cache.mkdir()
    kitpro_repo.render_template(
        profile / "pacman.conf.in", profile / "pacman.conf",
        {
            "CACHE_PATH": str(cache), "ARCH_GPG_PATH": "/etc/pacman.d/gnupg",
            "LOG_PATH": str(run_root / "archiso-pacman.log"),
            "SNAPSHOT_DATE": phase4_media.SNAPSHOT_DATE,
        },
    )
    (profile / "pacman.conf.in").unlink()
    project = profile / "airootfs/opt/kitpro-linux"
    project.mkdir(parents=True)
    _copy_runtime(source_root, project)
    _stage_operator_tooling(source_root, profile / "airootfs")
    shutil.copytree(bundle / "repo", project / "repo", symlinks=True)
    key_state = project / ".state/dev-keys"
    shutil.copytree(bundle / "trust/public", key_state / "public")
    shutil.copy2(bundle / "trust/keys.json", key_state / "keys.json")
    # Ship authoritative public trust material, not GnuPG's generated trust
    # database. phase4_live.prepare creates the verification-only client
    # keyring in the live overlay before any pacman operation.
    media = project / "media"
    media.mkdir()
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
            "profile_sha256": profile_hash,
            "build_configuration_sha256": configuration["build_configuration_sha256"],
        },
    )
    kitpro_repo.atomic_write_json(run_root / "bundle-verification.json", verification)
    return profile, configuration


def build(
    source_root: Path,
    bundle: Path,
    output_root: Path,
    build_id: str | None = None,
    *,
    keep_artifacts: bool = False,
    production_qualification: bool = False,
    release_policy: Path | None = None,
) -> dict[str, Any]:
    state_maintenance.prepare_heavy_work(output_root)
    started = _utc_now()
    started_monotonic = time.monotonic()
    build_id = build_id or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_root = output_root / "runs" / build_id
    if run_root.exists():
        raise kitpro_repo.PipelineError(f"build ID already exists: {build_id}")
    run_root.mkdir(parents=True)
    failed_stage = "worker-validation"
    failed_command: list[str] | None = None
    exit_code: int | None = None
    try:
        worker_report = worker_check.build_report(run_root)
        kitpro_repo.atomic_write_json(run_root / "worker-capability.json", worker_report)
        worker_check.validate_report(worker_report)
        if worker_report["worker"]["archiso"] != EXPECTED_ARCHISO:
            raise kitpro_repo.PipelineError(
                f"expected archiso {EXPECTED_ARCHISO}, found {worker_report['worker']['archiso']}"
            )
        failed_stage = "build-input-validation"
        if production_qualification or release_policy is not None:
            from tools.production_media import stage_qualification_profile
            profile, configuration = stage_qualification_profile(source_root, bundle, run_root, release_policy)
        else:
            profile, configuration = stage_native_profile(source_root, bundle, run_root)
        generation = configuration["stable_generation"]
        iso_name = configuration.get("iso_filename", ISO_NAME)
        media_version = configuration["media_version"]
        squashfs_options = effective_squashfs_options(profile / "profiledef.sh")
        squashfs_processors = validate_squashfs_processor_policy(squashfs_options)
        cpu_topology = _cpu_topology()
        workspace_findings = _scan_secrets(profile)
        if workspace_findings:
            raise kitpro_repo.PipelineError(
                f"build-workspace secret scan found prohibited content: {workspace_findings}"
            )
        kitpro_repo.atomic_write_json(
            run_root / "workspace-secret-scan.json",
            {"schema_version": 1, "status": "passed", "findings": []},
        )
        work = run_root / "work"
        output = run_root / "out"
        output.mkdir()
        source_epoch = (configuration["source_date_epoch"] if production_qualification or release_policy is not None else
                       kitpro_repo.load_json(
                           bundle / "repo/stable" / RELEASE / GENERATION / "manifest.json"
                       )["source_epoch"])
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = str(source_epoch)
        environment["TZ"] = "UTC"
        wrapper_root = run_root / "reproducible-tools"
        wrapper_root.mkdir()
        mkfs_fat = Path(shutil.which("mkfs.fat") or "")
        if not mkfs_fat.is_file():
            raise kitpro_repo.PipelineError("mkfs.fat is unavailable")
        wrapper = wrapper_root / "mkfs.fat"
        kitpro_repo.atomic_write(
            wrapper,
            (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f"exec {mkfs_fat} --invariant \"$@\"\n"
            ).encode(),
            0o755,
        )
        xorriso = Path(shutil.which("xorriso") or "")
        if not xorriso.is_file():
            raise kitpro_repo.PipelineError("xorriso is unavailable")
        xorriso_wrapper = wrapper_root / "xorriso"
        kitpro_repo.atomic_write(
            xorriso_wrapper,
            (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "fixed_date=$(date -u -d \"@${SOURCE_DATE_EPOCH:?}\" +%Y%m%d%H%M%S00)\n"
                "args=()\n"
                "while (( $# )); do\n"
                "  args+=(\"$1\")\n"
                "  if [[ $1 == -as && ${2:-} == mkisofs ]]; then\n"
                "    shift\n"
                "    args+=(\"$1\" --set_all_file_dates \"$fixed_date\")\n"
                "  fi\n"
                "  shift\n"
                "done\n"
                f"exec {xorriso} \"${{args[@]}}\"\n"
            ).encode(),
            0o755,
        )
        environment["PATH"] = f"{wrapper_root}:{environment['PATH']}"
        failed_stage = "native-archiso-build"
        command = ["mkarchiso", "-v", "-r", "-w", str(work), "-o", str(output), str(profile)]
        failed_command = command
        kitpro_repo.atomic_write(run_root / "mkarchiso-command.json", kitpro_repo.canonical_json_bytes(command))
        with (run_root / "mkarchiso.log").open("w") as log:
            result = subprocess.run(
                command, cwd=source_root, env=environment, text=True,
                stdout=log, stderr=subprocess.STDOUT, check=False, timeout=2400,
            )
        exit_code = result.returncode
        if result.returncode != 0:
            raise kitpro_repo.PipelineError(f"mkarchiso failed ({result.returncode})")
        logged_squashfs_processors = _squashfs_processors_from_log(
            (run_root / "mkarchiso.log").read_text()
        )
        iso = output / iso_name
        if not iso.is_file():
            raise kitpro_repo.PipelineError(f"mkarchiso did not create expected ISO: {iso}")
        manifest: dict[str, Any] = {
            "schema_version": 1, "build_id": build_id, "status": "passed",
            "git_commit": configuration["source_git_commit"], "git_tree_state": "clean",
            "source_date_epoch": source_epoch,
            "worker_identity": worker_report["worker"],
            "worker_capability_report_sha256": worker_report["report_sha256"],
            "archiso_version": worker_report["worker"]["archiso"],
            "qemu_version": worker_report["worker"]["qemu"],
            "firmware_version": worker_report["worker"]["ovmf"],
            "stable_generation": generation,
            "generation_manifest_sha256": configuration["generation_manifest_sha256"],
            "package_artifact_set_sha256": configuration["generation_artifact_set_sha256"],
            "profile_sha256": configuration["profile_sha256"],
            "build_configuration_sha256": configuration["build_configuration_sha256"],
            "installer_version": media_version,
            "installer_source_sha256": configuration["installation_engine_sha256"],
            "cpu_topology": cpu_topology,
            "squashfs_options": squashfs_options,
            "squashfs_processors": squashfs_processors,
            "squashfs_log_confirmed_processors": logged_squashfs_processors,
            "iso_filename": iso_name, "iso_path": str(iso),
            "iso_size_bytes": iso.stat().st_size, "iso_sha256": kitpro_repo.sha256_file(iso),
            "boot_mode_inspection": "pending-static-verification",
            "build_method": "native-mkarchiso", "privilege_model": worker_report["capabilities"]["privilege_model"],
            "build_start": started, "build_end": _utc_now(),
            "build_duration_seconds": round(time.monotonic() - started_monotonic, 3),
        }
        validate_build_manifest(manifest, expected_generation=generation)
        kitpro_repo.atomic_write_json(run_root / "build-manifest.json", manifest)
        state_maintenance.cleanup_generated_tree(
            work, allowed_root=run_root, keep_artifacts=keep_artifacts
        )
        state_maintenance.cleanup_generated_tree(
            profile, allowed_root=run_root, keep_artifacts=keep_artifacts
        )
        return manifest
    except Exception as error:
        failure = {
            "schema_version": 1, "status": "failed", "build_id": build_id,
            "failed_stage": failed_stage, "command": failed_command, "exit_code": exit_code,
            "error": str(error), "source_commit": _git_state(source_root)[0],
            "build_start": started, "failed_at": _utc_now(),
        }
        kitpro_repo.atomic_write_json(run_root / "failure.json", failure)
        raise


def _run_logged(command: list[str], log: Path) -> str:
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    kitpro_repo.atomic_write(log, result.stdout.encode())
    if result.returncode != 0:
        raise kitpro_repo.PipelineError(f"command failed ({result.returncode}): {' '.join(command)}")
    return result.stdout


def _remove_readonly_extraction(path: Path) -> None:
    """Remove only a verifier-created extraction tree whose ISO modes are read-only."""
    resolved = path.resolve()
    if not resolved.exists():
        return
    if not resolved.is_dir() or resolved == Path("/") or len(resolved.parts) < 4:
        raise kitpro_repo.PipelineError(f"refusing unsafe extraction cleanup target: {resolved}")
    for directory in sorted(
        (item for item in resolved.rglob("*") if item.is_dir() and not item.is_symlink()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(directory.stat().st_mode | 0o700)
    resolved.chmod(resolved.stat().st_mode | 0o700)
    shutil.rmtree(resolved)


def validate_build_manifest(manifest: dict[str, Any], *, expected_generation: str = GENERATION) -> None:
    required = {
        "schema_version", "build_id", "status", "git_commit", "git_tree_state",
        "source_date_epoch", "worker_identity", "worker_capability_report_sha256",
        "archiso_version", "qemu_version", "firmware_version", "stable_generation",
        "generation_manifest_sha256", "package_artifact_set_sha256", "profile_sha256",
        "build_configuration_sha256", "installer_version", "installer_source_sha256",
        "cpu_topology", "squashfs_options", "squashfs_processors",
        "squashfs_log_confirmed_processors",
        "iso_filename", "iso_path", "iso_size_bytes", "iso_sha256",
        "boot_mode_inspection", "build_method", "privilege_model", "build_start",
        "build_end", "build_duration_seconds",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise kitpro_repo.PipelineError(f"Phase 5 build manifest misses fields: {missing}")
    if manifest["schema_version"] != 1 or manifest["status"] != "passed":
        raise kitpro_repo.PipelineError("Phase 5 build manifest did not pass")
    if manifest["git_tree_state"] != "clean" or manifest["build_method"] != "native-mkarchiso":
        raise kitpro_repo.PipelineError("Phase 5 build manifest records an unqualified build")
    if manifest["stable_generation"] != expected_generation:
        raise kitpro_repo.PipelineError("Phase 5 build manifest changed Stable generation")
    if validate_squashfs_processor_policy(manifest["squashfs_options"]) != manifest["squashfs_processors"]:
        raise kitpro_repo.PipelineError("Phase 5 build manifest changed SquashFS processor policy")
    if not manifest["squashfs_log_confirmed_processors"] or any(
        value != SQUASHFS_PROCESSORS
        for value in manifest["squashfs_log_confirmed_processors"]
    ):
        raise kitpro_repo.PipelineError("Phase 5 build manifest lacks effective SquashFS processor proof")
    if not all(
        isinstance(manifest["cpu_topology"].get(field), int)
        and manifest["cpu_topology"][field] > 0
        for field in ("proc_cpuinfo_logical_processors", "nproc")
    ):
        raise kitpro_repo.PipelineError("Phase 5 build manifest lacks CPU-topology evidence")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["git_commit"]):
        raise kitpro_repo.PipelineError("Phase 5 build manifest has an invalid Git commit")
    for field in (
        "worker_capability_report_sha256", "generation_manifest_sha256",
        "package_artifact_set_sha256", "profile_sha256", "build_configuration_sha256",
        "installer_source_sha256", "iso_sha256",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(manifest[field])):
            raise kitpro_repo.PipelineError(f"Phase 5 build manifest has an invalid hash: {field}")


def _boot_mode_checks(xorriso_report: str) -> tuple[bool, bool]:
    boot_lines = [
        line for line in xorriso_report.splitlines()
        if line.startswith("El Torito boot img :")
    ]
    uefi = any(re.search(r"(?:\sUEFI\s|platform_id=0xEF)", line, re.IGNORECASE) for line in boot_lines)
    bios = any(re.search(r"(?:\sBIOS\s|platform_id=0x00)", line, re.IGNORECASE) for line in boot_lines)
    return uefi, not bios


def _scan_secrets(root: Path) -> list[dict[str, str]]:
    forbidden_files = {"id_rsa", "id_ed25519", "secring.gpg"}
    forbidden_directories = {"private-keys-v1.d", "openpgp-revocs.d"}
    patterns = {
        "private-key-armor": re.compile(br"-----BEGIN (?:PGP |OPENSSH |RSA |EC )?PRIVATE KEY"),
        "github-token": re.compile(br"gh[opusr]_[A-Za-z0-9]{24,}"),
        "generic-token": re.compile(br"(?i)(?:api[_-]?key|access[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9_./+-]{20,}"),
    }
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        private_directory = next((part for part in path.parts if part in forbidden_directories), None)
        if path.name in forbidden_files or (
            private_directory is not None and (path.is_file() or (path.is_dir() and any(path.iterdir())))
        ):
            findings.append({"path": relative, "kind": "private-key-path"})
        if not path.is_file() or path.is_symlink():
            continue
        matches: set[str] = set()
        overlap = b""
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                data = overlap + chunk
                for name, pattern in patterns.items():
                    if name not in matches and pattern.search(data):
                        matches.add(name)
                overlap = data[-512:]
        findings.extend({"path": relative, "kind": name} for name in sorted(matches))
    return findings


def _verify_embedded_repository(
    rootfs: Path,
    scratch: Path,
    generation: str = GENERATION,
) -> dict[str, Any]:
    project = rootfs / "opt/kitpro-linux"
    repo = project / "repo"
    key_state = project / ".state/dev-keys"
    manifest_path = repo / "stable" / RELEASE / generation / "manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    kitpro_repo.validate_manifest(manifest)
    gpg_home = scratch / "embedded-public-gnupg"
    kitpro_repo.setup_kitpro_keyring(gpg_home, key_state / "public")
    keys = kitpro_repo.load_json(key_state / "keys.json")
    for digest in kitpro_repo.manifest_object_hashes(manifest):
        artifact = kitpro_repo.object_path(repo, digest)
        if not artifact.is_file() or kitpro_repo.sha256_file(artifact) != digest:
            raise kitpro_repo.PipelineError(f"embedded repository object is corrupt: {digest}")
    generation_root = manifest_path.parent
    for repository in manifest["repositories"]:
        repository_root = generation_root / "core/os" / repository["architecture"]
        for package in repository["packages"]:
            signer = _verify_public_signature(
                gpg_home, repository_root / package["kitpro_signature"]["filename"],
                repository_root / package["filename"],
            )
            if signer != keys["roles"]["package"]["fingerprint"]:
                raise kitpro_repo.PipelineError(f"wrong embedded package signer: {package['name']}")
        database = repository["database"]
        signer = _verify_public_signature(
            gpg_home, repository_root / database["signature_filename"],
            repository_root / database["filename"],
        )
        if signer != keys["roles"]["repository"]["fingerprint"]:
            raise kitpro_repo.PipelineError("wrong embedded repository database signer")
    return {
        "status": "passed",
        "generation_manifest_sha256": kitpro_repo.sha256_file(manifest_path),
        "artifact_set_sha256": kitpro_repo.manifest_artifact_hash(manifest),
        "package_count": sum(len(repository["packages"]) for repository in manifest["repositories"]),
    }


def _verify_media_contents(
    iso: Path,
    bundle: Path,
    output: Path,
    generation: str = GENERATION,
) -> dict[str, Any]:
    """Apply the common static content checks without changing build qualification."""
    extraction = output / "iso"
    rootfs = output / "rootfs"
    output.mkdir(parents=True, exist_ok=False)
    el_torito = _run_logged(
        ["xorriso", "-indev", str(iso), "-report_el_torito", "plain", "-report_system_area", "plain"],
        output / "boot-metadata.txt",
    )
    _run_logged(
        ["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(extraction)],
        output / "iso-extraction.log",
    )
    squashfs_candidates = list(extraction.glob("*/x86_64/airootfs.sfs"))
    if len(squashfs_candidates) != 1:
        raise kitpro_repo.PipelineError("ISO does not contain exactly one Archiso root filesystem")
    _run_logged(["unsquashfs", "-d", str(rootfs), str(squashfs_candidates[0])], output / "unsquashfs.log")
    squashfs_sha256 = kitpro_repo.sha256_file(squashfs_candidates[0])
    iso_content_sha256 = _inventory_hash(_rootfs_content_inventory(extraction))
    with tempfile.TemporaryDirectory(prefix="phase5-boot-", dir=output) as temporary:
        boot_images = Path(temporary)
        _run_logged(
            [
                "xorriso", "-osirrox", "on", "-indev", str(iso),
                "-extract_boot_images", str(boot_images),
            ],
            output / "boot-images-extraction.log",
        )
        boot_images_sha256 = _inventory_hash(_rootfs_content_inventory(boot_images))
    uefi, bios_absent = _boot_mode_checks(el_torito)
    required = {
        "kernel": any(extraction.glob("*/boot/x86_64/vmlinuz-linux-lts")),
        "initramfs": any(extraction.glob("*/boot/x86_64/initramfs-linux-lts.img")),
        "installer": (rootfs / "usr/local/bin/kitpro-install").is_file(),
        "guided_installer": (rootfs / "usr/local/bin/kitpro-installer").is_file(),
        "rescue": (rootfs / "usr/local/bin/kitpro-rescue").is_file(),
        "schema": (rootfs / "opt/kitpro-linux/schemas/install-spec-v1.schema.json").is_file(),
        "recovery_receipt_schema": (
            rootfs / "opt/kitpro-linux/schemas/recovery-receipt.schema.json"
        ).is_file(),
        "rescue_health_schema": (
            rootfs / "opt/kitpro-linux/schemas/rescue-health.schema.json"
        ).is_file(),
        "support_bundle_manifest_schema": (
            rootfs / "opt/kitpro-linux/schemas/support-bundle-manifest.schema.json"
        ).is_file(),
        "support_bundle_inspection_schema": (
            rootfs / "opt/kitpro-linux/schemas/support-bundle-inspection.schema.json"
        ).is_file(),
        "support_bundle_command_current": (
            rootfs / "usr/bin/kitpro-support-bundle"
        ).is_file() and kitpro_repo.sha256_file(
            rootfs / "usr/bin/kitpro-support-bundle"
        ) == kitpro_repo.sha256_file(PROJECT_ROOT / "runtime/kitpro-support-bundle"),
        "support_bundle_runtime_current": (
            rootfs / "usr/lib/kitpro-linux/support-bundle"
        ).is_file() and kitpro_repo.sha256_file(
            rootfs / "usr/lib/kitpro-linux/support-bundle"
        ) == kitpro_repo.sha256_file(PROJECT_ROOT / "runtime/support-bundle"),
        "support_bundle_inspector_current": (
            rootfs / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py"
        ).is_file() and kitpro_repo.sha256_file(
            rootfs / "usr/lib/kitpro-linux/python/tools/support_bundle_inspect.py"
        ) == kitpro_repo.sha256_file(PROJECT_ROOT / "tools/support_bundle_inspect.py"),
        "health_command_current": (
            rootfs / "usr/bin/kitpro-health"
        ).is_file() and kitpro_repo.sha256_file(
            rootfs / "usr/bin/kitpro-health"
        ) == kitpro_repo.sha256_file(PROJECT_ROOT / "runtime/kitpro-health"),
        "kernel_status_command_current": (
            rootfs / "usr/bin/kitpro-kernel-status"
        ).is_file() and kitpro_repo.sha256_file(
            rootfs / "usr/bin/kitpro-kernel-status"
        ) == kitpro_repo.sha256_file(PROJECT_ROOT / "runtime/kitpro-kernel-status"),
        "embedded_generation": (
            rootfs / f"opt/kitpro-linux/repo/stable/{RELEASE}/{generation}/manifest.json"
        ).is_file(),
        "uefi": uefi,
        "bios_absent": bios_absent,
        "generated_client_keyring_absent": not (
            rootfs / "opt/kitpro-linux/.state/client/gnupg"
        ).exists(),
        "ldconfig_aux_cache_absent": not (
            rootfs / "var/cache/ldconfig/aux-cache"
        ).exists(),
    }
    if not all(required.values()):
        raise kitpro_repo.PipelineError(f"static media requirements failed: {required}")
    operator_tooling = phase4_media.validate_live_operator_tooling(rootfs)
    help_result = subprocess.run(
        ["chroot", str(rootfs), "/usr/bin/kitpro-support-bundle", "--help"],
        env={"PATH": "/usr/bin:/bin", "HOME": "/root"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=15,
    )
    kitpro_repo.atomic_write(
        output / "support-bundle-help.txt", help_result.stdout.encode()
    )
    if help_result.returncode != 0 or "kitpro-support-bundle verify ARCHIVE" not in help_result.stdout:
        raise kitpro_repo.PipelineError(
            "built media support-bundle wrapper cannot execute its canonical runtime"
        )
    required["operator_tooling_modes"] = True
    required["support_bundle_help"] = True
    support_runtime = (rootfs / "usr/lib/kitpro-linux/support-bundle").read_text()
    if not all(
        marker in support_runtime
        for marker in (
            "VERSION=0.4",
            'kitpro-support-bundle inspect ARCHIVE [--json] [--verbose]',
            'kitpro-support-bundle view ARCHIVE MEMBER [--pretty]',
            'kitpro-support-bundle view ARCHIVE --list',
        )
    ):
        raise kitpro_repo.PipelineError("ISO carries an incomplete support-bundle inspection runtime")
    os_release = (rootfs / "etc/os-release").read_text()
    if "ID=kitpro-linux-installer" not in os_release:
        raise kitpro_repo.PipelineError("ISO carries the wrong live-system identity")
    pacman_config = rootfs / "etc/pacman.conf"
    repositories = __import__("tools.kitpro_phase2", fromlist=["x"]).parse_enabled_repositories(pacman_config)
    if repositories != ["kitpro-0.1-dev-core"] or "SigLevel = Required DatabaseRequired TrustedOnly" not in pacman_config.read_text():
        raise kitpro_repo.PipelineError("ISO repository configuration is not KITPro-only with required signatures")
    verification = _verify_embedded_repository(
        rootfs, output / "embedded-signature-verification", generation
    )
    bundle_manifest = kitpro_repo.load_json(bundle / "input-bundle.json")
    if (
        verification["generation_manifest_sha256"] != bundle_manifest["generation_manifest_sha256"]
        or verification["artifact_set_sha256"] != bundle_manifest["artifact_set_sha256"]
    ):
        raise kitpro_repo.PipelineError("embedded repository differs from the selected input bundle")
    findings = _scan_secrets(extraction)
    if findings:
        raise kitpro_repo.PipelineError(f"secret scan found prohibited content: {findings}")
    report = {
        "schema_version": 1, "status": "passed", "iso_filename": iso.name,
        "iso_sha256": kitpro_repo.sha256_file(iso), "stable_generation": generation,
        "checks": required, "identity": "kitpro-linux-installer",
        "enabled_repositories": repositories, "signatures": verification,
        "operator_tooling": operator_tooling,
        "secret_scan": {"status": "passed", "findings": []},
        "boot_metadata_sha256": kitpro_repo.sha256_file(output / "boot-metadata.txt"),
        "squashfs_sha256": squashfs_sha256,
        "iso_content_sha256": iso_content_sha256,
        "boot_images_sha256": boot_images_sha256,
    }
    kitpro_repo.atomic_write_json(output / "static-media-validation.json", report)
    _remove_readonly_extraction(extraction)
    _remove_readonly_extraction(rootfs)
    return report


def verify_media(build_manifest_path: Path, bundle: Path, output: Path) -> dict[str, Any]:
    """Verify media from a qualified native Phase 5 build."""
    build_manifest = kitpro_repo.load_json(build_manifest_path)
    iso = Path(build_manifest["iso_path"])
    if not iso.is_file() or kitpro_repo.sha256_file(iso) != build_manifest["iso_sha256"]:
        raise kitpro_repo.PipelineError("ISO does not match its build manifest")
    try:
        report = _verify_media_contents(
            iso, bundle, output, build_manifest.get("stable_generation", GENERATION)
        )
    finally:
        _remove_readonly_extraction(output / "iso")
        _remove_readonly_extraction(output / "rootfs")
        _remove_readonly_extraction(output / "embedded-signature-verification")
    build_manifest["boot_mode_inspection"] = "uefi-only-verified"
    validate_build_manifest(build_manifest)
    kitpro_repo.atomic_write_json(build_manifest_path, build_manifest)
    return report


def verify_development_media(
    media_report_path: Path,
    bundle: Path,
    output: Path,
) -> dict[str, Any]:
    """Verify seeded-root development media without claiming native qualification."""
    media_report = kitpro_repo.load_json(media_report_path)
    phase4_media.validate_build_report(media_report)
    iso = Path(media_report["iso_path"])
    if not iso.is_absolute():
        iso = PROJECT_ROOT / iso
    if not iso.is_file() or kitpro_repo.sha256_file(iso) != media_report["iso_sha256"]:
        raise kitpro_repo.PipelineError("ISO does not match its development media report")
    try:
        report = _verify_media_contents(
            iso, bundle, output, media_report.get("stable_generation", GENERATION)
        )
    finally:
        _remove_readonly_extraction(output / "iso")
        _remove_readonly_extraction(output / "rootfs")
        _remove_readonly_extraction(output / "embedded-signature-verification")
    report.update(
        {
            "source_git_commit": media_report["source_git_commit"],
            "media_version": media_report["media_version"],
            "build_method": "unprivileged-seeded-root",
            "qualification_scope": "local-development-only",
        }
    )
    kitpro_repo.atomic_write_json(output / "static-media-validation.json", report)
    return report


def compare_builds(first_path: Path, second_path: Path, output: Path) -> dict[str, Any]:
    first = kitpro_repo.load_json(first_path)
    second = kitpro_repo.load_json(second_path)
    input_fields = (
        "git_commit", "source_date_epoch", "stable_generation", "generation_manifest_sha256",
        "package_artifact_set_sha256", "profile_sha256", "build_configuration_sha256",
        "installer_source_sha256", "archiso_version",
        "squashfs_options", "squashfs_processors",
    )
    input_match = all(first[field] == second[field] for field in input_fields)
    if not input_match:
        raise kitpro_repo.PipelineError("cannot compare builds made from different inputs")
    report = {
        "schema_version": 1, "status": "passed", "inputs_identical": True,
        "first": {field: first[field] for field in ("build_id", "iso_size_bytes", "iso_sha256")},
        "second": {field: second[field] for field in ("build_id", "iso_size_bytes", "iso_sha256")},
        "iso_bit_for_bit_identical": first["iso_sha256"] == second["iso_sha256"],
        "iso_sizes_identical": first["iso_size_bytes"] == second["iso_size_bytes"],
        "installed_package_sets_identical": first["package_artifact_set_sha256"] == second["package_artifact_set_sha256"],
        "known_difference_categories": [],
    }
    if not report["iso_bit_for_bit_identical"]:
        first_iso = Path(first["iso_path"])
        second_iso = Path(second["iso_path"])
        if first_iso.is_file() and second_iso.is_file():
            report["deep_comparison"] = _deep_iso_comparison(first_iso, second_iso, output.parent)
            deep = report["deep_comparison"]
            if not deep["boot_metadata_identical"]:
                report["known_difference_categories"].append("boot metadata")
            if not deep["iso_inventory_identical"]:
                report["known_difference_categories"].append("ISO directory metadata or layout")
            if not deep["squashfs_image_identical"]:
                category = (
                    "SquashFS container metadata"
                    if deep["rootfs_content_identical"] else "generated live-root content"
                )
                report["known_difference_categories"].append(category)
        else:
            report["known_difference_categories"] = [
                "deep comparison unavailable because ISO paths are not accessible",
            ]
    kitpro_repo.atomic_write_json(output, report)
    return report


def _command_text(command: list[str]) -> str:
    result = subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"reproducibility inspection failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def _rootfs_content_inventory(root: Path) -> list[dict[str, Any]]:
    return [
        record for record in _inventory(root)
        if record["type"] != "directory"
    ]


def _normalized_xorriso_report(report: str) -> str:
    """Remove invocation context that is not stored ISO metadata."""
    ignored = ("Drive current:", "Media summary:")
    return "\n".join(
        line for line in report.splitlines()
        if not line.startswith(ignored)
    ) + "\n"


def _deep_iso_comparison(first: Path, second: Path, evidence_root: Path) -> dict[str, Any]:
    evidence_root.mkdir(parents=True, exist_ok=True)
    labels = (("first", first), ("second", second))
    measurements: dict[str, dict[str, Any]] = {}
    inventories: dict[str, list[dict[str, Any]]] = {}
    iso_inventories: dict[str, list[dict[str, Any]]] = {}
    boot_inventories: dict[str, list[dict[str, Any]]] = {}
    with tempfile.TemporaryDirectory(prefix="phase5-repro-", dir=evidence_root) as temporary:
        temporary_root = Path(temporary)
        for label, iso in labels:
            listing = _command_text(["xorriso", "-indev", str(iso), "-find", "/", "-exec", "lsdl"])
            boot = _command_text(
                ["xorriso", "-indev", str(iso), "-report_el_torito", "plain", "-report_system_area", "plain"]
            )
            normalized_listing = _normalized_xorriso_report(listing)
            normalized_boot = _normalized_xorriso_report(boot)
            kitpro_repo.atomic_write(evidence_root / f"{label}-iso-inventory.txt", listing.encode())
            kitpro_repo.atomic_write(evidence_root / f"{label}-boot-metadata.txt", boot.encode())
            iso_tree = temporary_root / f"{label}-iso"
            _command_text(
                ["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(iso_tree)]
            )
            iso_content = _rootfs_content_inventory(iso_tree)
            iso_inventories[label] = iso_content
            boot_tree = temporary_root / f"{label}-boot-images"
            boot_tree.mkdir()
            _command_text(
                ["xorriso", "-osirrox", "on", "-indev", str(iso),
                 "-extract_boot_images", str(boot_tree)]
            )
            boot_content = _rootfs_content_inventory(boot_tree)
            boot_inventories[label] = boot_content
            squashfs = temporary_root / f"{label}.sfs"
            _command_text(
                ["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract_single",
                 "/kitpro/x86_64/airootfs.sfs", str(squashfs)]
            )
            extracted = temporary_root / f"{label}-rootfs"
            _command_text(["unsquashfs", "-d", str(extracted), str(squashfs)])
            content_inventory = _rootfs_content_inventory(extracted)
            inventories[label] = content_inventory
            measurements[label] = {
                "iso_inventory_sha256": kitpro_repo.sha256_bytes(normalized_listing.encode()),
                "boot_metadata_sha256": kitpro_repo.sha256_bytes(normalized_boot.encode()),
                "squashfs_sha256": kitpro_repo.sha256_file(squashfs),
                "rootfs_content_sha256": _inventory_hash(content_inventory),
                "rootfs_entry_count": len(content_inventory),
                "iso_content_sha256": _inventory_hash(iso_content),
                "iso_content_entry_count": len(iso_content),
                "boot_images_sha256": _inventory_hash(boot_content),
                "boot_image_entry_count": len(boot_content),
            }
    first_by_path = {item["path"]: item for item in inventories["first"]}
    second_by_path = {item["path"]: item for item in inventories["second"]}
    changed_paths = sorted(
        path for path in first_by_path.keys() | second_by_path.keys()
        if first_by_path.get(path) != second_by_path.get(path)
    )
    first_iso_by_path = {item["path"]: item for item in iso_inventories["first"]}
    second_iso_by_path = {item["path"]: item for item in iso_inventories["second"]}
    changed_iso_paths = sorted(
        path for path in first_iso_by_path.keys() | second_iso_by_path.keys()
        if first_iso_by_path.get(path) != second_iso_by_path.get(path)
    )
    first_boot_by_path = {item["path"]: item for item in boot_inventories["first"]}
    second_boot_by_path = {item["path"]: item for item in boot_inventories["second"]}
    changed_boot_paths = sorted(
        path for path in first_boot_by_path.keys() | second_boot_by_path.keys()
        if first_boot_by_path.get(path) != second_boot_by_path.get(path)
    )
    return {
        "first": measurements["first"], "second": measurements["second"],
        "iso_inventory_identical": (
            measurements["first"]["iso_inventory_sha256"]
            == measurements["second"]["iso_inventory_sha256"]
        ),
        "boot_metadata_identical": (
            measurements["first"]["boot_metadata_sha256"]
            == measurements["second"]["boot_metadata_sha256"]
        ),
        "squashfs_image_identical": (
            measurements["first"]["squashfs_sha256"]
            == measurements["second"]["squashfs_sha256"]
        ),
        "rootfs_content_identical": not changed_paths,
        "iso_content_identical": not changed_iso_paths,
        "boot_images_identical": not changed_boot_paths,
        "changed_rootfs_path_count": len(changed_paths),
        "changed_rootfs_paths": changed_paths[:200],
        "changed_rootfs_paths_truncated": len(changed_paths) > 200,
        "changed_iso_path_count": len(changed_iso_paths),
        "changed_iso_paths": changed_iso_paths[:200],
        "changed_iso_paths_truncated": len(changed_iso_paths) > 200,
        "changed_boot_image_path_count": len(changed_boot_paths),
        "changed_boot_image_paths": changed_boot_paths[:200],
        "changed_boot_image_paths_truncated": len(changed_boot_paths) > 200,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bundle_create = commands.add_parser("bundle-create")
    bundle_create.add_argument("output", type=Path)
    bundle_create.add_argument("--repo-root", type=Path, default=PROJECT_ROOT / "repo")
    bundle_create.add_argument("--key-state", type=Path, default=PROJECT_ROOT / ".state/dev-keys")
    bundle_create.add_argument("--generation", default=GENERATION)
    bundle_verify = commands.add_parser("bundle-verify")
    bundle_verify.add_argument("bundle", type=Path)
    bundle_verify.add_argument("--scratch", type=Path, default=DEFAULT_STATE / "bundle-verify")
    bundle_verify.add_argument("--generation", default=GENERATION)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--bundle", type=Path, required=True)
    build_parser.add_argument("--source-root", type=Path, default=PROJECT_ROOT)
    build_parser.add_argument("--output-root", type=Path, default=DEFAULT_STATE)
    build_parser.add_argument("--build-id")
    build_parser.add_argument("--keep-artifacts", action="store_true")
    static = commands.add_parser("verify-media")
    static.add_argument("build_manifest", type=Path)
    static.add_argument("--bundle", type=Path, required=True)
    static.add_argument("--output", type=Path, required=True)
    development_static = commands.add_parser("verify-development-media")
    development_static.add_argument("media_report", type=Path)
    development_static.add_argument("--bundle", type=Path, required=True)
    development_static.add_argument("--output", type=Path, required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    compare.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "bundle-create":
            result = create_bundle(
                args.output.resolve(), args.repo_root.resolve(), args.key_state.resolve(), args.generation
            )
        elif args.command == "bundle-verify":
            result = verify_bundle(args.bundle.resolve(), args.scratch.resolve(), args.generation)
        elif args.command == "build":
            result = build(
                args.source_root.resolve(),
                args.bundle.resolve(),
                args.output_root.resolve(),
                args.build_id,
                keep_artifacts=args.keep_artifacts,
            )
        elif args.command in {"verify-media", "verify-development-media"}:
            try:
                if args.command == "verify-media":
                    result = verify_media(
                        args.build_manifest.resolve(), args.bundle.resolve(), args.output.resolve()
                    )
                else:
                    result = verify_development_media(
                        args.media_report.resolve(), args.bundle.resolve(), args.output.resolve()
                    )
            except Exception as error:
                args.output.mkdir(parents=True, exist_ok=True)
                kitpro_repo.atomic_write_json(
                    args.output / "failure.json",
                    {
                        "schema_version": 1, "status": "failed",
                        "failed_stage": "static-media-validation", "error": str(error),
                        "input_report": str(
                            args.build_manifest
                            if args.command == "verify-media"
                            else args.media_report
                        ),
                        "failed_at": _utc_now(),
                    },
                )
                raise
        else:
            result = compare_builds(args.first.resolve(), args.second.resolve(), args.output.resolve())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
