"""Execute a validated install plan and record machine-readable evidence."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from tools import kitpro_phase2, kitpro_repo
from tools.install.disk import assert_disk_unchanged, discover_disk, require_erase_authorization
from tools.install.model import InstallSpec
from tools.install.plan import load_plan, validate_plan
from tools.install.receipt import build_receipt
from tools.install.rootfs import BASE_ARTIFACTS, STATE_ROOT, stage_rootfs, validate_install_source


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = STATE_ROOT / "evidence"
INSTALLATION_ROOT = STATE_ROOT / "installations"
STAGES = (
    "planning", "rootfs_staging", "configuration", "boot_setup", "partitioning",
    "rootfs_deployment", "validation", "completed",
)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_path(plan: dict[str, Any]) -> Path:
    return INSTALLATION_ROOT / f"{plan['plan_sha256']}.json"


def _evidence_directory(plan: dict[str, Any]) -> Path:
    return EVIDENCE_ROOT / plan["plan_sha256"]


def write_state(plan: dict[str, Any], stage: str, result: str = "running", error: str | None = None) -> None:
    if stage not in (*STAGES, "failed"):
        raise kitpro_repo.PipelineError(f"unknown installation stage: {stage}")
    path = _state_path(plan)
    previous: dict[str, Any] | None = kitpro_repo.load_json(path) if path.is_file() else None
    started = previous["started_at"] if previous else _now()
    document = {
        "schema_version": 1,
        "plan_sha256": plan["plan_sha256"],
        "target": plan["target"]["path"],
        "stage": stage,
        "result": result,
        "started_at": started,
        "updated_at": _now(),
        "error": error,
        "disk_may_be_modified": bool(previous and previous.get("disk_may_be_modified"))
        or stage in {"partitioning", "rootfs_deployment", "validation", "completed"},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(path, document)


def _refuse_prior_state(plan: dict[str, Any]) -> None:
    path = _state_path(plan)
    if path.is_file():
        state = kitpro_repo.load_json(path)
        raise kitpro_repo.PipelineError(
            f"installation state already exists at stage {state['stage']}; generate a new plan before erasing again"
        )


def render_repart_definitions(root: Path, plan: dict[str, Any], *, populate: bool = True) -> Path:
    definitions = root / "repart.d"
    definitions.mkdir(parents=True, exist_ok=False)
    esp = plan["partition_table"]["esp"]
    root_partition = plan["partition_table"]["root"]
    kitpro_repo.atomic_write(
        definitions / "00-esp.conf",
        (
            "[Partition]\nType=esp\nLabel=KITPRO_ESP\n"
            f"UUID={esp['partition_uuid']}\nFormat=vfat\nCopyFiles=/efi/:/\n"
            "SizeMinBytes=256M\nSizeMaxBytes=256M\n"
        ).encode(),
    )
    kitpro_repo.atomic_write(
        definitions / "10-root.conf",
        (
            "[Partition]\nType=root-x86-64\nLabel=KITPRO_ROOT\n"
            f"UUID={root_partition['partition_uuid']}\nFormat=ext4\nCopyFiles=/:/\n"
            "ExcludeFiles=/efi\nSizeMinBytes=5G\nGrowFileSystem=yes\n"
        ).encode(),
    )
    if not populate:
        for path in definitions.glob("*.conf"):
            text = "\n".join(line for line in path.read_text().splitlines()
                             if not line.startswith(("CopyFiles=", "ExcludeFiles="))) + "\n"
            path.write_text(text)
    return definitions


def _mtools_environment() -> dict[str, str]:
    environment = os.environ.copy()
    mtools = kitpro_phase2.mtools_path(PROJECT_ROOT / ".state/phase2")
    if mtools:
        environment["PATH"] = f"{mtools}:{environment['PATH']}"
    environment["SYSTEMD_LOG_TARGET"] = "console"
    return environment


def _recorded_command(
    command: list[str],
    evidence: Path,
    name: str,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    kitpro_repo.atomic_write(evidence / f"{name}.stdout", completed.stdout.encode())
    kitpro_repo.atomic_write(evidence / f"{name}.stderr", completed.stderr.encode())
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"{name} failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return completed


def _block_tree(target: Path, evidence: Path, name: str) -> list[dict[str, Any]]:
    completed = _recorded_command(
        ["lsblk", "-J", "-b", "-o", "PATH,TYPE,SIZE,MOUNTPOINTS", str(target)],
        evidence,
        name,
    )
    try:
        roots = json.loads(completed.stdout).get("blockdevices", [])
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("lsblk returned invalid block-tree JSON") from error
    flattened: list[dict[str, Any]] = []

    def visit(items: list[dict[str, Any]]) -> None:
        for item in items:
            flattened.append(item)
            children = item.get("children") or []
            if isinstance(children, list):
                visit(children)

    if not isinstance(roots, list):
        raise kitpro_repo.PipelineError("lsblk returned an invalid block-tree inventory")
    visit(roots)
    return flattened


def _device_is_swap(device: Path, target: Path) -> bool:
    swaps = Path("/proc/swaps")
    if not swaps.is_file():
        return False
    for line in swaps.read_text().splitlines()[1:]:
        fields = line.split()
        if not fields or not fields[0].startswith("/dev/"):
            continue
        source = Path(fields[0]).resolve()
        if source == device:
            return True
        completed = subprocess.run(
            ["lsblk", "-s", "-n", "-o", "PATH", str(source)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode == 0 and str(target) in completed.stdout.splitlines():
            return True
    return False


def _assert_block_target_idle(
    target: Path,
    evidence: Path,
    *,
    require_no_children: bool,
    name: str,
) -> list[dict[str, Any]]:
    devices = _block_tree(target, evidence, name)
    if not devices or Path(str(devices[0].get("path", ""))).resolve() != target.resolve():
        raise kitpro_repo.PipelineError("block target identity disappeared during synchronization")
    children = devices[1:]
    mounts = sorted(
        {
            mount
            for device in devices
            for mount in (device.get("mountpoints") or [])
            if mount
        }
    )
    if mounts:
        raise kitpro_repo.PipelineError(f"block target became mounted: {mounts}")
    if _device_is_swap(target.resolve(), target.resolve()):
        raise kitpro_repo.PipelineError("block target or a child device is active swap")
    holders: list[str] = []
    for device in devices:
        device_path = Path(str(device.get("path", "")))
        holder_root = Path("/sys/class/block") / device_path.name / "holders"
        if holder_root.is_dir():
            holders.extend(str(path) for path in holder_root.iterdir())
    if holders:
        raise kitpro_repo.PipelineError(f"block target has active holders: {sorted(holders)}")
    if require_no_children and children:
        child_paths = sorted(str(item.get("path")) for item in children)
        raise kitpro_repo.PipelineError(
            f"stale partition devices remain after table reread: {child_paths}"
        )
    return devices


def _prepare_block_target(target: Path, expected: dict[str, Any], evidence: Path) -> None:
    if os.geteuid() != 0:
        raise kitpro_repo.PipelineError("block-device installation requires root privileges")
    before = target.stat()
    _assert_block_target_idle(
        target, evidence, require_no_children=False, name="block-target-before-wipe"
    )
    _recorded_command(
        ["wipefs", "--all", "--force", str(target)], evidence, "wipefs"
    )
    _recorded_command(
        ["udevadm", "settle", "--timeout=30"],
        evidence,
        "udevadm-settle-after-wipe",
    )
    _recorded_command(
        ["blockdev", "--rereadpt", str(target)], evidence, "blockdev-rereadpt"
    )
    _recorded_command(
        ["udevadm", "settle", "--timeout=30"],
        evidence,
        "udevadm-settle-after-reread",
    )
    after = target.stat()
    if before.st_rdev != after.st_rdev:
        raise kitpro_repo.PipelineError("block target device identity changed during synchronization")
    devices = _assert_block_target_idle(
        target, evidence, require_no_children=True, name="block-target-after-wipe"
    )
    if int(devices[0].get("size", -1)) != int(expected["size_bytes"]):
        raise kitpro_repo.PipelineError("block target size changed during synchronization")


def _run_repart(
    target: Path,
    target_type: str,
    staging_root: Path | None,
    definitions: Path,
    evidence: Path,
) -> list[dict[str, Any]]:
    offline = "yes" if target_type == "image" else "no"
    empty_mode = "force" if target_type == "image" else "require"
    command = [
        "systemd-repart", "--dry-run=no", f"--offline={offline}", f"--empty={empty_mode}",
        f"--definitions={definitions}",
        *([f"--copy-source={staging_root}"] if staging_root is not None else []),
        "--json=short", str(target),
    ]
    if target_type == "image":
        command = [
            "unshare", "--fork", "--pid", "--mount", "--map-auto", "--map-root-user",
            *command,
        ]
    elif os.geteuid() != 0:
        raise kitpro_repo.PipelineError("block-device installation requires root privileges")
    completed = subprocess.run(
        command,
        env=_mtools_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    kitpro_repo.atomic_write(evidence / "systemd-repart.stdout", completed.stdout.encode())
    kitpro_repo.atomic_write(evidence / "systemd-repart.stderr", completed.stderr.encode())
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"partitioning, formatting, or rootfs deployment failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise kitpro_repo.PipelineError("systemd-repart returned invalid JSON") from error
    if not isinstance(report, list):
        raise kitpro_repo.PipelineError("systemd-repart report is not a partition list")
    return report


@contextmanager
def mounted_install_target(target: Path, plan: dict[str, Any], evidence: Path):
    """Mount only the two fresh partitions belonging to the authorized disk."""
    _recorded_command(["udevadm", "settle", "--timeout=30"], evidence, "settle-after-format")
    result = _recorded_command(
        ["lsblk", "--tree", "-J", "-p", "-o", "PATH,TYPE,PARTUUID,FSTYPE,MOUNTPOINTS", str(target)],
        evidence, "formatted-target",
    )
    disks = json.loads(result.stdout)["blockdevices"]
    if len(disks) != 1 or Path(disks[0]["path"]).resolve() != target.resolve():
        raise kitpro_repo.PipelineError("formatted target identity mismatch")
    children = disks[0].get("children", [])
    devices = {}
    for role in ("root", "esp"):
        expected = plan["partition_table"][role]
        matches = [p for p in children if p.get("partuuid") == expected["partition_uuid"]
                   and p.get("fstype") == expected["filesystem"] and p.get("type") == "part"]
        if len(matches) != 1 or any(matches[0].get("mountpoints") or []):
            raise kitpro_repo.PipelineError("fresh target partition validation failed")
        devices[role] = matches[0]["path"]
    if len(children) != 2:
        raise kitpro_repo.PipelineError("unexpected target partition inventory")
    root = evidence / "mounted-target"
    root.mkdir()
    mounted = []
    try:
        for role, destination in (("root", root), ("esp", root / "efi")):
            destination.mkdir(exist_ok=True)
            _recorded_command(["mount", devices[role], str(destination)], evidence, "mount-" + role)
            mounted.append(destination)
        yield root
        for destination in reversed(mounted):
            _recorded_command(["sync", "-f", str(destination)], evidence, "sync-" + destination.name)
    finally:
        cleanup_errors = []
        keyring = root / "etc/pacman.d/gnupg"
        if keyring.is_dir():
            try:
                # These are the newly installed client's verification processes,
                # never an operator or production signing keyring. Repart used
                # to omit their sockets when copying the staged tree.
                _recorded_command(
                    ["gpgconf", "--homedir", str(keyring), "--kill", "all"],
                    evidence, "stop-target-keyring",
                )
            except kitpro_repo.PipelineError as error:
                cleanup_errors.append(str(error))
        for destination in reversed(mounted):
            try:
                _recorded_command(
                    ["umount", str(destination)], evidence, "unmount-" + destination.name
                )
            except kitpro_repo.PipelineError as error:
                cleanup_errors.append(str(error))
        if cleanup_errors:
            raise kitpro_repo.PipelineError("target unmount failed: " + "; ".join(cleanup_errors))


def _partition_report(target: Path, plan: dict[str, Any]) -> dict[str, Any]:
    table = kitpro_phase2.run(["parted", "-sm", str(target), "unit", "B", "print"]).stdout
    lines = [line for line in table.splitlines() if re.match(r"^[12]:", line)]
    if len(lines) != 2 or ":KITPRO_ESP:" not in lines[0] or ":KITPRO_ROOT:" not in lines[1]:
        raise kitpro_repo.PipelineError("installed target does not contain the expected two partitions")
    result: dict[str, Any] = {"partition_table": "gpt", "parted": table, "partitions": []}
    for name, line, expected in (
        ("esp", lines[0], plan["partition_table"]["esp"]),
        ("root", lines[1], plan["partition_table"]["root"]),
    ):
        fields = line.split(":")
        offset = int(fields[1].removesuffix("B"))
        size = int(fields[3].removesuffix("B"))
        filesystem_uuid = kitpro_phase2.run(
            ["blkid", "-p", "-o", "value", "-s", "UUID", "-O", str(offset), str(target)]
        ).stdout.strip()
        filesystem_type = kitpro_phase2.run(
            ["blkid", "-p", "-o", "value", "-s", "TYPE", "-O", str(offset), str(target)]
        ).stdout.strip()
        if not filesystem_uuid or filesystem_type != expected["filesystem"]:
            raise kitpro_repo.PipelineError(f"installed {name} filesystem validation failed")
        result["partitions"].append(
            {
                "name": name,
                "number": int(fields[0]),
                "offset_bytes": offset,
                "size_bytes": size,
                "partition_uuid": expected["partition_uuid"],
                "filesystem": filesystem_type,
                "filesystem_uuid": filesystem_uuid,
            }
        )
    return result


def validate_report(document: dict[str, Any]) -> None:
    required = {
        "schema_version", "installer_version", "install_spec_version", "install_spec_sha256",
        "install_plan_sha256", "release", "repository_generation", "package_count", "target",
        "disk", "rootfs_manifest_sha256", "kernel", "initramfs", "bootloader",
        "install_receipt", "system",
        "network", "ssh", "firewall", "start_time", "completion_time", "first_boot", "result",
    }
    missing = sorted(required - set(document))
    if missing:
        raise kitpro_repo.PipelineError(f"installation report misses fields: {missing}")
    if document["schema_version"] != 1 or document["install_spec_version"] != 1:
        raise kitpro_repo.PipelineError("unsupported installation report version")
    for field in ("install_spec_sha256", "install_plan_sha256", "rootfs_manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(document.get(field, ""))):
            raise kitpro_repo.PipelineError(f"installation report has an invalid hash: {field}")
    if document["result"] not in {"installed_pending_first_boot", "passed", "failed"}:
        raise kitpro_repo.PipelineError("installation report has an invalid result")
    bootloader = document["bootloader"]
    if not isinstance(bootloader, dict) or bootloader.get("name") != "systemd-boot" or not bootloader.get("version"):
        raise kitpro_repo.PipelineError("installation report has invalid bootloader evidence")
    receipt = document["install_receipt"]
    if (
        not isinstance(receipt, dict)
        or receipt.get("path") != "/var/lib/kitpro-linux/install-receipt.json"
        or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("sha256", "")))
    ):
        raise kitpro_repo.PipelineError("installation report has invalid receipt evidence")


def apply(
    spec: InstallSpec,
    plan: dict[str, Any],
    allow_disk_erase: bool,
    source_metadata: dict[str, Any] | None = None,
    stage_callback: Callable[[str], None] | None = None,
    administrator_password: str | None = None,
) -> tuple[Path, dict[str, Any]]:
    validate_plan(plan)
    if spec.sha256() != plan["install_spec_sha256"]:
        raise kitpro_repo.PipelineError("install specification does not match the plan")
    require_erase_authorization(allow_disk_erase)
    current = discover_disk(Path(spec.disk.device), spec.disk.target_type, spec.disk.minimum_capacity_bytes)
    assert_disk_unchanged(plan["target"], current)
    _refuse_prior_state(plan)
    evidence = _evidence_directory(plan)
    evidence.mkdir(parents=True, exist_ok=False)
    started = _now()
    receipt = build_receipt(
        plan, started, source_metadata or {"kind": "development-environment"}
    )
    stage = "planning"
    write_state(plan, stage)

    def transition(value: str) -> None:
        nonlocal stage
        stage = value
        write_state(plan, stage)
        if stage_callback:
            stage_callback(stage)

    try:
        stage_arguments: dict[str, Any] = {}
        if administrator_password is not None:
            stage_arguments["administrator_password"] = administrator_password
        if current.target_type == "block":
            validate_install_source(plan)
            # Integrity and the plan were checked before confirmation. Recheck
            # the physical identity immediately before the first disk mutation.
            latest = discover_disk(
                Path(current.path), current.target_type, spec.disk.minimum_capacity_bytes
            )
            assert_disk_unchanged(current.to_dict(), latest)
            transition("partitioning")
            _prepare_block_target(Path(current.path), current.to_dict(), evidence)
            definitions = render_repart_definitions(evidence, plan, populate=False)
            repart_report = _run_repart(Path(current.path), "block", None, definitions, evidence)
            transition("rootfs_deployment")
            with mounted_install_target(Path(current.path), plan, evidence) as target_root:
                staging_root, base_manifest, configuration = stage_rootfs(
                    spec, plan, receipt, transition, mounted_target=target_root, **stage_arguments
                )
        else:
            # Host-side image fixtures retain the established offline repart
            # path. Live whole-disk installs never enter this staging branch.
            transition("rootfs_staging")
            staging_root, base_manifest, configuration = stage_rootfs(
                spec, plan, receipt, transition, **stage_arguments
            )
            definitions = render_repart_definitions(staging_root.parent, plan)
            transition("partitioning")
            repart_report = _run_repart(
                Path(current.path), current.target_type, staging_root, definitions, evidence
            )
            transition("rootfs_deployment")
        transition("validation")
        disk = _partition_report(Path(current.path), plan)
        disk["systemd_repart"] = repart_report
        if current.target_type == "image":
            disk["image_sha256"] = kitpro_repo.sha256_file(Path(current.path))
        base_manifest_path = BASE_ARTIFACTS / "rootfs-manifest.json"
        report = {
            "schema_version": 1,
            "installer_version": plan["installer_version"],
            "install_spec_version": plan["install_spec_version"],
            "install_spec_sha256": plan["install_spec_sha256"],
            "install_plan_sha256": plan["plan_sha256"],
            "release": plan["release"],
            "repository_generation": plan["repository_generation"],
            "package_count": configuration["package_count"],
            "target": current.to_dict(),
            "disk": disk,
            "rootfs_manifest_sha256": kitpro_repo.sha256_file(base_manifest_path),
            "kernel": {
                "package": base_manifest["kernel"]["package"],
                "version": base_manifest["kernel"]["version"],
                "sha256": configuration["kernel_sha256"],
            },
            "initramfs": {
                "tool": base_manifest["initramfs"]["tool"],
                "sha256": configuration["initramfs_sha256"],
            },
            "bootloader": {
                "name": "systemd-boot",
                "version": base_manifest["build_tools"]["systemd"],
            },
            "install_receipt": {
                "path": "/var/lib/kitpro-linux/install-receipt.json",
                "sha256": configuration["install_receipt_sha256"],
            },
            "system": {
                "hostname": spec.system.hostname,
                "locale": spec.system.locale,
                "timezone": spec.system.timezone,
                "administrator": spec.administrator.username,
                "sudo": "wheel-password-required",
                "local_console_password": (
                    "enrolled"
                    if administrator_password is not None
                    or spec.administrator.password_hash is not None
                    else "locked"
                ),
            },
            "network": plan["network"],
            "ssh": plan["ssh"],
            "firewall": plan["firewall"],
            "start_time": started,
            "completion_time": _now(),
            "first_boot": {"status": "not_run", "checks": {}},
            "result": "installed_pending_first_boot",
        }
        validate_report(report)
        report_path = evidence / "installation-report.json"
        kitpro_repo.atomic_write_json(report_path, report)
        transition("completed")
        write_state(plan, "completed", "installed_pending_first_boot")
        return report_path, report
    except Exception as error:
        write_state(plan, "failed", "failed", f"{stage}: {error}")
        failure = {
            "schema_version": 1,
            "plan_sha256": plan["plan_sha256"],
            "failed_stage": stage,
            "disk_may_be_modified": kitpro_repo.load_json(_state_path(plan))["disk_may_be_modified"],
            "error": str(error),
            "time": _now(),
        }
        kitpro_repo.atomic_write_json(evidence / "failure.json", failure)
        raise


def update_first_boot_report(report_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    report = kitpro_repo.load_json(report_path)
    if report["target"]["target_type"] == "image":
        image = Path(report["target"]["path"])
        if not image.is_file():
            raise kitpro_repo.PipelineError(f"installed image is unavailable: {image}")
        report["disk"]["image_sha256"] = kitpro_repo.sha256_file(image)
    report["first_boot"] = result
    report["result"] = "passed" if result.get("status") == "passed" else "failed"
    report["completion_time"] = _now()
    validate_report(report)
    kitpro_repo.atomic_write_json(report_path, report)
    return report
