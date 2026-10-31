"""Execute a validated install plan and record machine-readable evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from tools import kitpro_phase2, kitpro_repo
from tools.install.disk import assert_disk_unchanged, discover_disk, require_erase_authorization
from tools.install.model import InstallSpec
from tools.install.plan import validate_plan
from tools.install.receipt import build_receipt
from tools.install.rootfs import BASE_ARTIFACTS, STATE_ROOT, stage_rootfs, validate_install_source

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = STATE_ROOT / "evidence"
INSTALLATION_ROOT = STATE_ROOT / "installations"
INSTALL_MOUNT_ROOT = Path("/run/kitpro-installations")
STAGES = (
    "planning",
    "rootfs_staging",
    "configuration",
    "boot_setup",
    "partitioning",
    "rootfs_deployment",
    "validation",
    "completed",
)


def _flatten_devices(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for device in devices:
        rows.append(device)
        rows.extend(_flatten_devices(device.get("children", [])))
    return rows


def _now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_path(plan: dict[str, Any]) -> Path:
    return INSTALLATION_ROOT / f"{plan['plan_sha256']}.json"


def _evidence_directory(plan: dict[str, Any]) -> Path:
    return EVIDENCE_ROOT / plan["plan_sha256"]


def _installation_mountpoint(plan: dict[str, Any]) -> Path:
    """Keep client GnuPG agent sockets below Linux's AF_UNIX path limit."""
    plan_sha256 = str(plan["plan_sha256"])
    if re.fullmatch(r"[0-9a-f]{64}", plan_sha256) is None:
        raise kitpro_repo.PipelineError("install plan has an invalid digest")
    return INSTALL_MOUNT_ROOT / plan_sha256[:16]


def write_state(
    plan: dict[str, Any], stage: str, result: str = "running", error: str | None = None
) -> None:
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
    table = plan["partition_table"]
    if table.get("storage_schema_version") in {5, 6}:
        labels = {"esp": "KITPRO_ESP", "lvm-pv": "KITPRO_LVM_PV"}
        for index, partition in enumerate(table["partitions"]):
            role = partition["role"]
            format_line = "Format=vfat\n" if role == "esp" else ""
            kitpro_repo.atomic_write(
                definitions / f"{index * 10:02d}-{role}.conf",
                (
                    "[Partition]\n"
                    f"Type={partition['partition_type']}\nLabel={labels[role]}\n"
                    f"UUID={partition['partition_uuid']}\n{format_line}"
                    f"SizeMinBytes={partition['planned_size_bytes']}\n"
                    f"SizeMaxBytes={partition['planned_size_bytes']}\n"
                ).encode(),
            )
        return definitions
    if table.get("storage_schema_version") == 4:
        labels = {
            "esp": "KITPRO_ESP",
            "root": "KITPRO_ROOT",
            "home": "KITPRO_HOME",
            "var": "KITPRO_VAR",
            "srv": "KITPRO_SRV",
            "swap": "KITPRO_SWAP",
        }
        mounted_roles = {
            item["role"]: item["mount_point"]
            for item in table["partitions"]
            if item.get("mount_point") and item["role"] not in {"esp", "root"}
        }
        for index, partition in enumerate(table["partitions"]):
            role = partition["role"]
            format_line = ""
            if not (role == "root" and "encryption" in table):
                format_line = f"Format={partition['filesystem']}\n"
            copy_lines = ""
            if populate and role == "esp":
                copy_lines = "CopyFiles=/efi/:/\n"
            elif populate and role == "root":
                copy_lines = "CopyFiles=/:/\nExcludeFiles=/efi\n" + "".join(
                    f"ExcludeFiles={mount}\n" for mount in mounted_roles.values()
                )
            elif populate and role != "swap" and partition.get("mount_point"):
                copy_lines = f"CopyFiles={partition['mount_point']}/:/\n"
            kitpro_repo.atomic_write(
                definitions / f"{index * 10:02d}-{role}.conf",
                (
                    "[Partition]\n"
                    f"Type={partition['partition_type']}\nLabel={labels[role]}\n"
                    f"UUID={partition['partition_uuid']}\n{format_line}{copy_lines}"
                    f"SizeMinBytes={partition['planned_size_bytes']}\n"
                    f"SizeMaxBytes={partition['planned_size_bytes']}\n"
                ).encode(),
            )
        if not populate:
            for path in definitions.glob("*.conf"):
                text = (
                    "\n".join(
                        line
                        for line in path.read_text().splitlines()
                        if not line.startswith(("CopyFiles=", "ExcludeFiles="))
                    )
                    + "\n"
                )
                path.write_text(text)
        return definitions
    esp = table["esp"]
    root_partition = table["root"]
    esp_size = esp["planned_size_bytes"] if "partitions" in table else "256M"
    kitpro_repo.atomic_write(
        definitions / "00-esp.conf",
        (
            "[Partition]\nType=esp\nLabel=KITPRO_ESP\n"
            f"UUID={esp['partition_uuid']}\nFormat=vfat\nCopyFiles=/efi/:/\n"
            f"SizeMinBytes={esp_size}\nSizeMaxBytes={esp_size}\n"
        ).encode(),
    )
    root_copy = "CopyFiles=/:/\nExcludeFiles=/efi\n" if populate else ""
    if populate:
        for partition in table.get("partitions", []):
            mount_point = partition.get("mount_point")
            if partition.get("role") not in {"esp", "root", "swap"} and mount_point:
                root_copy += f"ExcludeFiles={mount_point}\n"
    if "partitions" in table:
        root_size = root_partition["planned_size_bytes"]
        root_sizing = f"SizeMinBytes={root_size}\nSizeMaxBytes={root_size}\n"
    else:
        root_sizing = "SizeMinBytes=5G\nGrowFileSystem=yes\n"
    kitpro_repo.atomic_write(
        definitions / "10-root.conf",
        (
            "[Partition]\nType=root-x86-64\nLabel=KITPRO_ROOT\n"
            f"UUID={root_partition['partition_uuid']}\n"
            f"{'' if 'encryption' in table else 'Format=' + root_partition.get('filesystem', 'ext4') + chr(10)}"
            f"{root_copy}{root_sizing}"
        ).encode(),
    )
    optional = [
        partition
        for partition in table.get("partitions", [])
        if partition.get("role") not in {"esp", "root"}
    ]
    if not optional:
        optional = [table[role] for role in ("home", "swap") if role in table]
    labels = {
        "home": "KITPRO_HOME",
        "var": "KITPRO_VAR",
        "srv": "KITPRO_SRV",
        "swap": "KITPRO_SWAP",
    }
    legacy_order = {"home": 2, "swap": 3}
    for offset, partition in enumerate(optional, 2):
        role = (
            partition["role"]
            if "role" in partition
            else next(name for name in ("home", "swap") if table.get(name) is partition)
        )
        offset = legacy_order.get(role, offset)
        mount_point = partition.get("mount_point")
        copy = (
            f"CopyFiles={mount_point}/:/\n" if populate and role != "swap" and mount_point else ""
        )
        kitpro_repo.atomic_write(
            definitions / f"{offset * 10:02d}-{role}.conf",
            (
                "[Partition]\n"
                f"Type={partition.get('partition_type', role)}\n"
                f"Label={labels[role]}\nUUID={partition['partition_uuid']}\n"
                f"Format={partition.get('filesystem', 'swap' if role == 'swap' else 'ext4')}\n{copy}"
                f"SizeMinBytes={partition['planned_size_bytes']}\n"
                f"SizeMaxBytes={partition['planned_size_bytes']}\n"
            ).encode(),
        )
    if not populate:
        for path in definitions.glob("*.conf"):
            text = (
                "\n".join(
                    line
                    for line in path.read_text().splitlines()
                    if not line.startswith(("CopyFiles=", "ExcludeFiles="))
                )
                + "\n"
            )
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
        capture_output=True,
        check=False,
    )
    kitpro_repo.atomic_write(evidence / f"{name}.stdout", completed.stdout.encode())
    kitpro_repo.atomic_write(evidence / f"{name}.stderr", completed.stderr.encode())
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(
            f"{name} failed ({completed.returncode}): {completed.stderr.strip()}"
        )
    return completed


def _recorded_secret_command(
    command: list[str], secret: bytearray, evidence: Path, name: str
) -> subprocess.CompletedProcess[bytes]:
    """Run a command with a secret on stdin while recording only non-secret output."""
    completed = subprocess.run(
        command,
        input=bytes(secret),
        capture_output=True,
        check=False,
    )
    kitpro_repo.atomic_write(evidence / f"{name}.stdout", completed.stdout)
    kitpro_repo.atomic_write(evidence / f"{name}.stderr", completed.stderr)
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise kitpro_repo.PipelineError(f"{name} failed ({completed.returncode}): {message}")
    return completed


def _inner_root_filesystem(plan: dict[str, Any]) -> str:
    root = plan["partition_table"]["root"]
    inner_filesystem = root.get("inner_filesystem")
    if inner_filesystem is not None:
        return str(inner_filesystem)
    return str(root["filesystem"])


def _planned_partition_devices(
    target: Path, plan: dict[str, Any], evidence: Path
) -> dict[str, str]:
    _recorded_command(["udevadm", "settle", "--timeout=30"], evidence, "settle-after-format")
    result = _recorded_command(
        ["lsblk", "--tree", "-J", "-p", "-o", "PATH,TYPE,PARTUUID,FSTYPE,MOUNTPOINTS", str(target)],
        evidence,
        "formatted-target",
    )
    disks = json.loads(result.stdout)["blockdevices"]
    if len(disks) != 1 or Path(disks[0]["path"]).resolve() != target.resolve():
        raise kitpro_repo.PipelineError("formatted target identity mismatch")
    children = disks[0].get("children", [])
    table = plan["partition_table"]
    preservation = table.get("layout") == "preserve"
    expected_roles = [
        item["role"] for item in table.get("partitions", []) if item.get("action") != "preserve"
    ]
    if not expected_roles:
        expected_roles = [
            "esp",
            "root",
            *(["home"] if "home" in table else []),
            *(["swap"] if "swap" in table else []),
        ]
    devices: dict[str, str] = {}
    for role in expected_roles:
        expected = table[role]
        encrypted_root = role == "root" and "encryption" in table
        unformatted_lvm_pv = role == "lvm-pv" and "lvm" in table
        matches = [
            item
            for item in children
            if item.get("partuuid") == expected["partition_uuid"]
            and (
                ((encrypted_root or unformatted_lvm_pv) and not item.get("fstype"))
                or item.get("fstype") == expected["filesystem"]
            )
            and item.get("type") == "part"
        ]
        if len(matches) != 1 or any(matches[0].get("mountpoints") or []):
            raise kitpro_repo.PipelineError("fresh target partition validation failed")
        devices[role] = matches[0]["path"]
    if not preservation and len(children) != len(expected_roles):
        raise kitpro_repo.PipelineError("unexpected target partition inventory")
    return devices


@contextmanager
def prepared_lvm(
    target: Path,
    plan: dict[str, Any],
    evidence: Path,
    *,
    pv_device: Path | None = None,
):
    """Create and activate the exact linear LV set from an authoritative plan."""
    table = plan["partition_table"]
    lvm = table["lvm"]
    vg = lvm["volume_group"]
    if (
        subprocess.run(
            ["vgs", "--noheadings", vg],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    ):
        raise kitpro_repo.PipelineError(f"planned volume group already exists: {vg}")
    pv = (
        str(pv_device)
        if pv_device is not None
        else _planned_partition_devices(target, plan, evidence)["lvm-pv"]
    )
    _recorded_command(["pvcreate", "--yes", "--force", pv], evidence, "lvm-pvcreate")
    _recorded_command(
        [
            "vgcreate",
            "--physicalextentsize",
            f"{lvm['extent_size_bytes']}B",
            vg,
            pv,
        ],
        evidence,
        "lvm-vgcreate",
    )
    devices: dict[str, str] = {}
    try:
        for volume in lvm["logical_volumes"]:
            _recorded_command(
                [
                    "lvcreate",
                    "--yes",
                    "--zero",
                    "y",
                    "--extents",
                    str(volume["extent_count"]),
                    "--name",
                    volume["name"],
                    vg,
                ],
                evidence,
                "lvm-lvcreate-" + volume["role"],
            )
            device = volume["device"]
            if volume["filesystem"] == "ext4":
                _recorded_command(
                    ["mkfs.ext4", "-F", "-L", "KITPRO_" + volume["role"].upper(), device],
                    evidence,
                    "lvm-format-" + volume["role"],
                )
            else:
                _recorded_command(["mkswap", "-L", "KITPRO_SWAP", device], evidence, "lvm-swap")
            devices[volume["role"]] = device
        _recorded_command(["vgchange", "--activate", "y", vg], evidence, "lvm-activate")
        inventory = _recorded_command(
            [
                "lvs",
                "--reportformat",
                "json",
                "--units",
                "b",
                "--nosuffix",
                "--options",
                "vg_name,lv_name,lv_size,lv_attr",
                vg,
            ],
            evidence,
            "lvm-inventory",
        )
        try:
            reported = json.loads(inventory.stdout)["report"][0]["lv"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise kitpro_repo.PipelineError("LVM inventory output is invalid") from error
        expected = {
            volume["name"]: volume["extent_count"] * lvm["extent_size_bytes"]
            for volume in lvm["logical_volumes"]
        }
        observed = {
            item["lv_name"]: int(float(item["lv_size"]))
            for item in reported
            if item.get("vg_name") == vg and "a" in item.get("lv_attr", "")
        }
        if observed != expected:
            raise kitpro_repo.PipelineError("active LVM inventory differs from the plan")
        yield devices
    finally:
        _recorded_command(["vgchange", "--activate", "n", vg], evidence, "lvm-deactivate")


@contextmanager
def opened_encrypted_root(
    target: Path,
    plan: dict[str, Any],
    evidence: Path,
    passphrase: str,
):
    encryption = plan["partition_table"]["encryption"]
    encrypted_role = "lvm-pv" if "lvm" in plan["partition_table"] else "root"
    root_partition = _planned_partition_devices(target, plan, evidence)[encrypted_role]
    mapper_name = encryption["mapper_name"]
    mapper = Path("/dev/mapper") / mapper_name
    secret = bytearray(passphrase.encode("utf-8"))
    try:
        _recorded_secret_command(
            [
                "cryptsetup",
                "luksFormat",
                "--batch-mode",
                "--type",
                "luks2",
                "--pbkdf",
                encryption["pbkdf"],
                "--iter-time",
                str(encryption["iter_time_ms"]),
                "--pbkdf-memory",
                str(encryption["pbkdf_memory_kib"]),
                "--pbkdf-parallel",
                str(encryption["pbkdf_parallel_threads"]),
                "--uuid",
                encryption["luks_uuid"],
                "--key-slot",
                str(encryption["keyslot"]),
                "--key-file",
                "-",
                root_partition,
            ],
            secret,
            evidence,
            "luks-format-root",
        )
        _recorded_secret_command(
            [
                "cryptsetup",
                "open",
                "--type",
                "luks2",
                "--key-file",
                "-",
                root_partition,
                mapper_name,
            ],
            secret,
            evidence,
            "luks-open-root",
        )
        if "lvm" not in plan["partition_table"]:
            filesystem = _inner_root_filesystem(plan)
            command = (
                ["mkfs.ext4", "-F", "-L", "KITPRO_ROOT", str(mapper)]
                if filesystem == "ext4"
                else ["mkfs.btrfs", "-f", "-L", "KITPRO_ROOT", str(mapper)]
            )
            _recorded_command(command, evidence, "format-decrypted-root")
        yield mapper
    finally:
        secret[:] = b"\0" * len(secret)
        if mapper.exists():
            _recorded_command(["cryptsetup", "close", mapper_name], evidence, "luks-close-root")


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
            capture_output=True,
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
        {mount for device in devices for mount in (device.get("mountpoints") or []) if mount}
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
    _recorded_command(["wipefs", "--all", "--force", str(target)], evidence, "wipefs")
    _recorded_command(
        ["udevadm", "settle", "--timeout=30"],
        evidence,
        "udevadm-settle-after-wipe",
    )
    _recorded_command(["blockdev", "--rereadpt", str(target)], evidence, "blockdev-rereadpt")
    _recorded_command(
        ["udevadm", "settle", "--timeout=30"],
        evidence,
        "udevadm-settle-after-reread",
    )
    after = target.stat()
    if before.st_rdev != after.st_rdev:
        raise kitpro_repo.PipelineError(
            "block target device identity changed during synchronization"
        )
    devices = _assert_block_target_idle(
        target, evidence, require_no_children=True, name="block-target-after-wipe"
    )
    if int(devices[0].get("size", -1)) != int(expected["size_bytes"]):
        raise kitpro_repo.PipelineError("block target size changed during synchronization")


def _prepare_preservation_target(
    target: Path, plan: dict[str, Any], evidence: Path
) -> list[dict[str, Any]]:
    """Apply only explicitly planned incremental GPT additions and formats."""
    if os.geteuid() != 0:
        raise kitpro_repo.PipelineError("block-device installation requires root privileges")
    if plan["partition_table"].get("layout") != "preserve":
        raise kitpro_repo.PipelineError("incremental partitioning requires a preservation plan")
    if shutil.which("sfdisk") is None:
        raise kitpro_repo.PipelineError("preservation mode requires sfdisk")
    _assert_block_target_idle(
        target, evidence, require_no_children=False, name="preservation-target-before-write"
    )
    type_guids = {
        "esp": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
        "root-x86-64": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
        "swap": "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f",
    }
    logical = int(plan["partition_table"]["logical_sector_bytes"])
    reports: list[dict[str, Any]] = []
    for partition in plan["partition_table"]["partitions"]:
        if partition.get("action") != "create":
            continue
        number = int(partition["partition_number"])
        script = (
            f"start={int(partition['start_bytes']) // logical}, "
            f"size={int(partition['size_bytes']) // logical}, "
            f"type={type_guids[partition['partition_type']]}, "
            f'uuid={partition["partition_uuid"]}, name="KITPRO_{partition["role"].upper()}"\n'
        )
        completed = subprocess.run(
            [
                "sfdisk",
                "--no-reread",
                "--wipe",
                "never",
                "--wipe-partitions",
                "never",
                "-N",
                str(number),
                str(target),
            ],
            input=script,
            text=True,
            capture_output=True,
            check=False,
        )
        kitpro_repo.atomic_write(evidence / f"sfdisk-create-{number}.stdin", script.encode())
        kitpro_repo.atomic_write(
            evidence / f"sfdisk-create-{number}.stdout", completed.stdout.encode()
        )
        kitpro_repo.atomic_write(
            evidence / f"sfdisk-create-{number}.stderr", completed.stderr.encode()
        )
        if completed.returncode != 0:
            raise kitpro_repo.PipelineError(
                f"incremental partition creation failed ({completed.returncode}): "
                f"{completed.stderr.strip()}"
            )
        reports.append(
            {
                "partition_number": number,
                "start_bytes": partition["start_bytes"],
                "size_bytes": partition["size_bytes"],
                "partition_uuid": partition["partition_uuid"],
                "action": "create",
            }
        )
    if reports:
        _recorded_command(
            ["blockdev", "--rereadpt", str(target)], evidence, "preserve-rereadpt"
        )
    _recorded_command(["udevadm", "settle", "--timeout=30"], evidence, "preserve-settle")
    devices = _recorded_command(
        ["lsblk", "-J", "-p", "-o", "PATH,PARTUUID", str(target)],
        evidence,
        "preserve-partition-identities",
    )
    rows = _flatten_devices(json.loads(devices.stdout).get("blockdevices", []))
    by_uuid = {str(row.get("partuuid")): str(row.get("path")) for row in rows}
    labels = {"esp": "KITPRO_ESP", "root": "KITPRO_ROOT", "swap": "KITPRO_SWAP"}
    for partition in plan["partition_table"]["partitions"]:
        if partition.get("action") not in {"create", "format"}:
            continue
        device = by_uuid.get(str(partition["partition_uuid"]))
        if not device:
            raise kitpro_repo.PipelineError(
                "authorized partition identity was not found after GPT update"
            )
        filesystem = partition["filesystem"]
        command = {
            "vfat": ["mkfs.fat", "-F", "32", "-n", labels[partition["role"]], device],
            "ext4": ["mkfs.ext4", "-F", "-L", labels[partition["role"]], device],
            "btrfs": ["mkfs.btrfs", "-f", "-L", labels[partition["role"]], device],
            "swap": ["mkswap", "-L", labels[partition["role"]], device],
        }.get(filesystem)
        if command is None:
            raise kitpro_repo.PipelineError(f"unsupported preservation filesystem: {filesystem}")
        _recorded_command(
            command, evidence, f"format-{partition['role']}-{partition['partition_number']}"
        )
    _recorded_command(["udevadm", "settle", "--timeout=30"], evidence, "preserve-settle-format")
    return reports


def _snapshot_reused_esp(
    target: Path,
    plan: dict[str, Any],
    evidence: Path,
    name: str,
    *,
    reject_collisions: bool = False,
) -> dict[str, str]:
    esp = plan["partition_table"]["esp"]
    if esp.get("action") != "reuse":
        return {}
    device = _planned_partition_devices(target, plan, evidence)["esp"]
    INSTALL_MOUNT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    mountpoint = INSTALL_MOUNT_ROOT / f"esp-audit-{plan['plan_sha256'][:12]}"
    mountpoint.mkdir(mode=0o700, exist_ok=False)
    try:
        _recorded_command(
            ["mount", "-o", "ro", device, str(mountpoint)], evidence, f"mount-{name}-esp"
        )
        snapshot = {
            str(path.relative_to(mountpoint)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(mountpoint.rglob("*"))
            if path.is_file()
        }
        if reject_collisions:
            stats = os.statvfs(mountpoint)
            available = stats.f_bavail * stats.f_frsize
            if available < 128 * 1024**2:
                raise kitpro_repo.PipelineError(
                    "reused EFI partition has less than 128 MiB available for KITPro boot files"
                )
            reserved = {
                "EFI/BOOT/BOOTX64.EFI",
                "EFI/systemd/systemd-bootx64.efi",
                "loader/loader.conf",
            }
            if any(
                path in reserved or path.startswith(("EFI/KITPRO/", "loader/entries/kitpro-"))
                for path in snapshot
            ):
                raise kitpro_repo.PipelineError(
                    "reused EFI partition contains paths reserved by KITPro; create a new EFI partition"
                )
        kitpro_repo.atomic_write_json(evidence / f"{name}-esp-files.json", snapshot)
        return snapshot
    finally:
        if mountpoint.is_mount():
            _recorded_command(["umount", str(mountpoint)], evidence, f"unmount-{name}-esp")
        mountpoint.rmdir()


def _install_reused_esp_boot_entry(target: Path, plan: dict[str, Any], evidence: Path) -> None:
    esp = plan["partition_table"]["esp"]
    if esp.get("action") != "reuse":
        return
    if shutil.which("efibootmgr") is None:
        raise kitpro_repo.PipelineError("EFI reuse requires efibootmgr")
    before = _recorded_command(["efibootmgr", "-v"], evidence, "efibootmgr-before")
    if re.search(
        r"KITPro Linux.*\\EFI\\KITPRO\\kitpro-bootx64\.efi",
        before.stdout,
        re.IGNORECASE,
    ):
        raise kitpro_repo.PipelineError("a KITPro UEFI boot entry already exists")
    _recorded_command(
        [
            "efibootmgr",
            "--create",
            "--disk",
            str(target),
            "--part",
            str(esp["partition_number"]),
            "--label",
            "KITPro Linux",
            "--loader",
            r"\EFI\KITPRO\kitpro-bootx64.efi",
        ],
        evidence,
        "efibootmgr-create-kitpro",
    )
    after = _recorded_command(["efibootmgr", "-v"], evidence, "efibootmgr-after")
    if not re.search(
        r"KITPro Linux.*\\EFI\\KITPRO\\kitpro-bootx64\.efi",
        after.stdout,
        re.IGNORECASE,
    ):
        raise kitpro_repo.PipelineError("KITPro UEFI boot entry was not created")


def _validate_reused_esp_result(before: dict[str, str], after: dict[str, str]) -> None:
    loader = "EFI/KITPRO/kitpro-bootx64.efi"
    if loader not in after:
        raise kitpro_repo.PipelineError("reused EFI partition lacks the KITPro boot manager")
    changed = sorted(path for path, digest in before.items() if after.get(path) != digest)
    if changed:
        raise kitpro_repo.PipelineError(
            "reused EFI partition changed pre-existing files: " + ", ".join(changed)
        )


def _assert_sector_geometry(target: Path, plan: dict[str, Any], evidence: Path) -> None:
    table = plan["partition_table"]
    if "storage_schema_version" not in table:
        return
    logical = _recorded_command(
        ["blockdev", "--getss", str(target)], evidence, "blockdev-logical-sector"
    )
    physical = _recorded_command(
        ["blockdev", "--getpbsz", str(target)], evidence, "blockdev-physical-sector"
    )
    try:
        current = (int(logical.stdout.strip()), int(physical.stdout.strip()))
    except ValueError as error:
        raise kitpro_repo.PipelineError("block target sector geometry is invalid") from error
    planned = (table["logical_sector_bytes"], table["physical_sector_bytes"])
    if current != planned:
        raise kitpro_repo.PipelineError(
            f"block target sector geometry changed: planned {planned}, observed {current}"
        )


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
        "systemd-repart",
        "--dry-run=no",
        f"--offline={offline}",
        f"--empty={empty_mode}",
        f"--definitions={definitions}",
        *([f"--copy-source={staging_root}"] if staging_root is not None else []),
        "--json=short",
        str(target),
    ]
    if target_type == "image":
        command = [
            "unshare",
            "--fork",
            "--pid",
            "--mount",
            "--map-auto",
            "--map-root-user",
            *command,
        ]
    elif os.geteuid() != 0:
        raise kitpro_repo.PipelineError("block-device installation requires root privileges")
    completed = subprocess.run(
        command,
        env=_mtools_environment(),
        text=True,
        capture_output=True,
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
def mounted_install_target(
    target: Path,
    plan: dict[str, Any],
    evidence: Path,
    *,
    root_device: Path | None = None,
    device_overrides: dict[str, str] | None = None,
):
    """Mount only the fresh planned filesystems belonging to the authorized disk."""
    table = plan["partition_table"]
    devices = _planned_partition_devices(target, plan, evidence)
    if device_overrides:
        devices.update(device_overrides)
    if root_device is not None:
        devices["root"] = str(root_device)
    root = _installation_mountpoint(plan)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700)
    mounted = []
    try:
        if _inner_root_filesystem(plan) == "btrfs":
            top_level = root.parent / f"{root.name}-btrfs-top"
            top_level.mkdir(mode=0o700)
            _recorded_command(
                ["mount", "-o", "subvolid=5", devices["root"], str(top_level)],
                evidence,
                "mount-btrfs-top",
            )
            try:
                for subvolume in table["subvolumes"]:
                    _recorded_command(
                        ["btrfs", "subvolume", "create", str(top_level / subvolume["name"])],
                        evidence,
                        "create-subvolume-" + subvolume["name"].removeprefix("@"),
                    )
            finally:
                _recorded_command(["umount", str(top_level)], evidence, "unmount-btrfs-top")
                top_level.rmdir()
            root_options = ["subvol=@"]
            if table["compression"] == "zstd":
                root_options.append("compress=zstd")
            _recorded_command(
                ["mount", "-o", ",".join(root_options), devices["root"], str(root)],
                evidence,
                "mount-root",
            )
            mounted.append(root)
            for subvolume in table["subvolumes"]:
                if subvolume["mount_point"] == "/":
                    continue
                destination = root / subvolume["mount_point"].removeprefix("/")
                destination.mkdir(parents=True, exist_ok=True)
                options = [f"subvol={subvolume['name']}"]
                if table["compression"] == "zstd":
                    options.append("compress=zstd")
                _recorded_command(
                    ["mount", "-o", ",".join(options), devices["root"], str(destination)],
                    evidence,
                    "mount-subvolume-" + subvolume["name"].removeprefix("@"),
                )
                mounted.append(destination)
            destinations = [
                (item["role"], root / item["mount_point"].removeprefix("/"))
                for item in table.get("partitions", [])
                if item["role"] not in {"esp", "root", "swap"}
                and item.get("mount_point") not in {None, "/", "/efi", "swap"}
                and item.get("action") != "preserve"
            ]
        else:
            destinations = [("root", root)]
            extra_roles = (
                [
                    item["role"]
                    for item in table["lvm"]["logical_volumes"]
                    if item["role"] not in {"root", "swap"}
                ]
                if "lvm" in table
                else [
                    item["role"]
                    for item in table.get("partitions", [])
                    if item["role"] not in {"esp", "root", "swap"}
                    and item.get("mount_point") not in {None, "/", "/efi", "swap"}
                    and item.get("action") != "preserve"
                ]
            )
            if not extra_roles and "home" in devices:
                extra_roles = ["home"]
            for role in sorted(extra_roles, key=lambda name: table[name]["mount_point"].count("/")):
                destinations.append((role, root / table[role]["mount_point"].removeprefix("/")))
        destinations.append(("esp", root / "efi"))
        for role, destination in destinations:
            destination.mkdir(exist_ok=True)
            _recorded_command(["mount", devices[role], str(destination)], evidence, "mount-" + role)
            mounted.append(destination)
        yield root
        for destination in reversed(mounted):
            _recorded_command(
                ["sync", "-f", str(destination)], evidence, "sync-" + destination.name
            )
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
                    evidence,
                    "stop-target-keyring",
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
    if plan["partition_table"].get("layout") == "preserve":
        current = discover_disk(target, "block", 0)
        observed = {item["partition_uuid"]: item for item in current.to_dict()["partitions"]}
        verified = []
        for expected in plan["partition_table"]["partitions"]:
            actual = observed.get(expected["partition_uuid"])
            if actual is None:
                raise kitpro_repo.PipelineError(
                    "planned partition is missing after preservation install"
                )
            if int(actual["start_bytes"]) != int(expected["start_bytes"]) or int(
                actual["size_bytes"]
            ) != int(expected["size_bytes"]):
                raise kitpro_repo.PipelineError("preserved partition geometry changed")
            if expected.get("action") in {"preserve", "reuse"} and (
                actual.get("filesystem_uuid") != expected.get("filesystem_uuid")
                or actual.get("filesystem") != expected.get("observed_filesystem")
                or actual.get("filesystem_label") != expected.get("label")
            ):
                raise kitpro_repo.PipelineError("preserved filesystem identity changed")
            verified.append(
                {
                    "name": expected["role"],
                    "number": expected["partition_number"],
                    "offset_bytes": actual["start_bytes"],
                    "size_bytes": actual["size_bytes"],
                    "partition_uuid": actual["partition_uuid"],
                    "filesystem": actual.get("filesystem"),
                    "filesystem_uuid": actual.get("filesystem_uuid"),
                    "action": expected["action"],
                }
            )
        return {
            "partition_table": "gpt",
            "partitions": verified,
            "preservation": plan["partition_table"]["preservation"],
        }
    table = kitpro_phase2.run(["parted", "-sm", str(target), "unit", "B", "print"]).stdout
    lines = [line for line in table.splitlines() if re.match(r"^[1-9][0-9]*:", line)]
    roles = [item["role"] for item in plan["partition_table"].get("partitions", [])]
    if not roles:
        roles = ["esp", "root"]
        if "home" in plan["partition_table"]:
            roles.append("home")
        if "swap" in plan["partition_table"]:
            roles.append("swap")
    labels = {
        "esp": "KITPRO_ESP",
        "root": "KITPRO_ROOT",
        "home": "KITPRO_HOME",
        "var": "KITPRO_VAR",
        "srv": "KITPRO_SRV",
        "swap": "KITPRO_SWAP",
        "lvm-pv": "KITPRO_LVM_PV",
    }
    if len(lines) != len(roles) or any(
        f":{labels[role]}:" not in line for role, line in zip(roles, lines, strict=True)
    ):
        raise kitpro_repo.PipelineError("installed target does not match the planned partitions")
    result: dict[str, Any] = {"partition_table": "gpt", "parted": table, "partitions": []}
    for name, line in zip(roles, lines, strict=True):
        expected = plan["partition_table"][name]
        fields = line.split(":")
        offset = int(fields[1].removesuffix("B"))
        size = int(fields[3].removesuffix("B"))
        if "partitions" in plan["partition_table"] and (
            offset != expected["start_bytes"] or size != expected["planned_size_bytes"]
        ):
            raise kitpro_repo.PipelineError(
                f"installed {name} boundaries differ from the authoritative plan"
            )
        filesystem_uuid = kitpro_phase2.run(
            ["blkid", "-p", "-o", "value", "-s", "UUID", "-O", str(offset), str(target)]
        ).stdout.strip()
        filesystem_type = kitpro_phase2.run(
            ["blkid", "-p", "-o", "value", "-s", "TYPE", "-O", str(offset), str(target)]
        ).stdout.strip()
        expected_filesystem = expected["filesystem"]
        if not filesystem_uuid or filesystem_type != expected_filesystem:
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
        "schema_version",
        "installer_version",
        "install_spec_version",
        "install_spec_sha256",
        "install_plan_sha256",
        "release",
        "repository_generation",
        "package_count",
        "target",
        "disk",
        "rootfs_manifest_sha256",
        "kernel",
        "initramfs",
        "bootloader",
        "install_receipt",
        "system",
        "network",
        "ssh",
        "firewall",
        "start_time",
        "completion_time",
        "first_boot",
        "result",
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
    if (
        not isinstance(bootloader, dict)
        or bootloader.get("name") != "systemd-boot"
        or not bootloader.get("version")
    ):
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
    luks_passphrase: str | None = None,
    precommit_guard: Callable[[Path, Any], None] | None = None,
) -> tuple[Path, dict[str, Any]]:
    validate_plan(plan)
    if spec.sha256() != plan["install_spec_sha256"]:
        raise kitpro_repo.PipelineError("install specification does not match the plan")
    require_erase_authorization(allow_disk_erase)
    current = discover_disk(
        Path(spec.disk.device), spec.disk.target_type, spec.disk.minimum_capacity_bytes
    )
    assert_disk_unchanged(plan["target"], current)
    _refuse_prior_state(plan)
    evidence = _evidence_directory(plan)
    evidence.mkdir(parents=True, exist_ok=False)
    started = _now()
    receipt = build_receipt(plan, started, source_metadata or {"kind": "development-environment"})
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
        preserved_esp_before: dict[str, str] = {}
        encrypted = "encryption" in plan["partition_table"]
        preservation = plan["partition_table"].get("layout") == "preserve"
        if encrypted and current.target_type != "block":
            raise kitpro_repo.PipelineError("encrypted installation requires a block-device target")
        if administrator_password is not None:
            stage_arguments["administrator_password"] = administrator_password
        if current.target_type == "block":
            validate_install_source(plan)
            root_filesystem = _inner_root_filesystem(plan)
            # Integrity and the plan were checked before confirmation. Recheck
            # the physical identity immediately before the first disk mutation.
            latest = discover_disk(
                Path(current.path), current.target_type, spec.disk.minimum_capacity_bytes
            )
            assert_disk_unchanged(current.to_dict(), latest)
            if precommit_guard is not None:
                precommit_guard(Path(current.path), latest)
            _assert_sector_geometry(Path(current.path), plan, evidence)
            if root_filesystem == "btrfs":
                missing = [tool for tool in ("mkfs.btrfs", "btrfs") if shutil.which(tool) is None]
                if missing:
                    raise kitpro_repo.PipelineError(
                        "Btrfs installation tooling is unavailable: " + ", ".join(missing)
                    )
            if encrypted:
                if not luks_passphrase:
                    raise kitpro_repo.PipelineError(
                        "encrypted installation requires a protected LUKS passphrase"
                    )
                if shutil.which("cryptsetup") is None:
                    raise kitpro_repo.PipelineError("LUKS2 installation tooling is unavailable")
            lvm_enabled = "lvm" in plan["partition_table"]
            if lvm_enabled:
                missing = [
                    tool
                    for tool in ("pvcreate", "vgcreate", "lvcreate", "vgchange")
                    if shutil.which(tool) is None
                ]
                if missing:
                    raise kitpro_repo.PipelineError(
                        "LVM2 installation tooling is unavailable: " + ", ".join(missing)
                    )
            transition("partitioning")
            if preservation:
                repart_report = _prepare_preservation_target(Path(current.path), plan, evidence)
                preserved_esp_before = _snapshot_reused_esp(
                    Path(current.path), plan, evidence, "before", reject_collisions=True
                )
            else:
                _prepare_block_target(Path(current.path), current.to_dict(), evidence)
                definitions = render_repart_definitions(evidence, plan, populate=False)
                repart_report = _run_repart(
                    Path(current.path), "block", None, definitions, evidence
                )
            transition("rootfs_deployment")
            if encrypted and lvm_enabled:
                with (
                    opened_encrypted_root(
                        Path(current.path), plan, evidence, luks_passphrase
                    ) as mapper,
                    prepared_lvm(
                        Path(current.path), plan, evidence, pv_device=mapper
                    ) as lvm_devices,
                    mounted_install_target(
                        Path(current.path), plan, evidence, device_overrides=lvm_devices
                    ) as target_root,
                ):
                    staging_root, base_manifest, configuration = stage_rootfs(
                        spec,
                        plan,
                        receipt,
                        transition,
                        mounted_target=target_root,
                        **stage_arguments,
                    )
            elif encrypted:
                with (
                    opened_encrypted_root(
                        Path(current.path), plan, evidence, luks_passphrase
                    ) as mapper,
                    mounted_install_target(
                        Path(current.path), plan, evidence, root_device=mapper
                    ) as target_root,
                ):
                    staging_root, base_manifest, configuration = stage_rootfs(
                        spec,
                        plan,
                        receipt,
                        transition,
                        mounted_target=target_root,
                        **stage_arguments,
                    )
            elif lvm_enabled:
                with (
                    prepared_lvm(Path(current.path), plan, evidence) as lvm_devices,
                    mounted_install_target(
                        Path(current.path), plan, evidence, device_overrides=lvm_devices
                    ) as target_root,
                ):
                    staging_root, base_manifest, configuration = stage_rootfs(
                        spec,
                        plan,
                        receipt,
                        transition,
                        mounted_target=target_root,
                        **stage_arguments,
                    )
            else:
                with mounted_install_target(Path(current.path), plan, evidence) as target_root:
                    staging_root, base_manifest, configuration = stage_rootfs(
                        spec,
                        plan,
                        receipt,
                        transition,
                        mounted_target=target_root,
                        **stage_arguments,
                    )
            if preservation:
                _install_reused_esp_boot_entry(Path(current.path), plan, evidence)
                preserved_esp_after = _snapshot_reused_esp(
                    Path(current.path), plan, evidence, "after"
                )
                _validate_reused_esp_result(preserved_esp_before, preserved_esp_after)
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
            "encryption": (
                {
                    "enabled": True,
                    "type": "luks2",
                    "luks_uuid": plan["partition_table"]["encryption"]["luks_uuid"],
                    "mapper_name": plan["partition_table"]["encryption"]["mapper_name"],
                    "root_filesystem": root_filesystem,
                }
                if encrypted
                else {"enabled": False}
            ),
            "lvm": plan["partition_table"].get("lvm", {"enabled": False}),
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
            "disk_may_be_modified": kitpro_repo.load_json(_state_path(plan))[
                "disk_may_be_modified"
            ],
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
