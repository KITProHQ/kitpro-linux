#!/usr/bin/env python3
"""Inventory KITPro generated state and guard storage-heavy work."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from tools import kitpro_repo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_ROOT = PROJECT_ROOT / ".state"
GIB = 1024**3
HARD_MINIMUM_BYTES = 75 * GIB
RECOMMENDED_BYTES = 150 * GIB
CATEGORIES = {
    "PRESERVE",
    "PRESERVE_LATEST",
    "EVIDENCE_RECORDED_REBUILDABLE",
    "FAILED_OR_SCRATCH",
    "UNKNOWN",
}

SIMPLE_PRESERVE = {
    "client", "dev-keys", "ingest", "kitpro-signatures", "maintenance", "native",
    "native-build",
}
PHASE_PRESERVE: dict[str, set[str]] = {
    "phase2": {
        "OVMF_VARS.4m.fd", "artifacts", "host-packages", "host-tools", "keys",
        "kitpro-linux-phase2.raw", "log", "rootfs", "rootfs-build-pacman.conf",
        "rootfs-cache", "update", "vm-tools", "vm-tools-cache", "vm-tools-pacman.conf",
    },
    "phase3": {
        "artifacts", "base-rootfs", "base-rootfs-artifacts", "evidence", "host-packages",
        "host-tools", "installations", "log", "rootfs-build-pacman.conf", "rootfs-cache",
    },
    "phase4": {
        "archiso-tools", "archiso-tools-pacman.conf", "artifacts", "empty-hooks", "log",
        "wrappers",
    },
    "phase5": {"input-g0002"},
    "phase6": {"bundle-store", "worker-rebuilds"},
    "phase7": {"runner-candidates", "secrets", "service-evidence"},
    "phase81": {"cache", "release-build", "release-package", "signatures"},
    "phase88": {"generation", "input-g0004", "rescue", "runs"},
}


def _utc(value: float) -> str:
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _du(path: Path, apparent: bool = False) -> int:
    command = ["du", "-x", "-B1", "-s"]
    if apparent:
        command.insert(1, "--apparent-size")
    completed = subprocess.run(
        [*command, str(path)], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False,
    )
    if not completed.stdout.strip():
        return 0
    return int(completed.stdout.split()[0])


def _phase(relative: Path) -> str:
    first = relative.parts[0]
    return first.removeprefix("phase") if first.startswith("phase") else "shared"


def _artifact_type(relative: Path) -> str:
    value = relative.as_posix()
    name = relative.name
    if name.endswith(".raw"):
        return "qemu-disk"
    if "/runs" in value or value.endswith("/runs"):
        return "acceptance-runs"
    if "/work" in value or value.endswith("/work"):
        return "build-workspace"
    if "/out/" in value:
        return "iso-output"
    if "qualification" in name:
        return "qualification-workspace"
    if "rootfs" in name:
        return "root-filesystem"
    if "bundle" in value or "fetched" in value or "retrieved" in value:
        return "repository-bundle"
    if "key" in value or "gnupg" in value or "signature" in value:
        return "trust-state"
    if "cache" in name:
        return "cache"
    return "generated-state"


def _latest_iso_root() -> Path | None:
    report = STATE_ROOT / "phase4/artifacts/media-build-report.json"
    if not report.is_file():
        return None
    iso = Path(kitpro_repo.load_json(report)["iso_path"])
    absolute = iso if iso.is_absolute() else PROJECT_ROOT / iso
    try:
        relative = absolute.resolve().relative_to((STATE_ROOT / "phase4/out").resolve())
    except ValueError:
        return None
    return STATE_ROOT / "phase4/out" / relative.parts[0]


def _latest_phase88_iso_run() -> Path | None:
    reports = sorted(
        (STATE_ROOT / "phase88/runs").glob("*/phase88-acceptance.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for report in reports:
        document = kitpro_repo.load_json(report)
        run_directory = document.get("iso_acceptance", {}).get("run_directory")
        if document.get("status") != "passed" or not isinstance(run_directory, str):
            continue
        absolute = PROJECT_ROOT / run_directory
        try:
            absolute.resolve().relative_to((STATE_ROOT / "phase88/iso/runs").resolve())
        except ValueError:
            continue
        return absolute
    return None


def inventory_units() -> list[Path]:
    units: list[Path] = []
    for child in sorted(STATE_ROOT.iterdir()):
        if child.name in SIMPLE_PRESERVE or child.name in {"reconstructed", "tmp"}:
            units.append(child)
            continue
        if child.name == "phase4":
            for phase_child in sorted(child.iterdir()):
                if phase_child.name == "out":
                    units.extend(sorted(phase_child.iterdir()))
                else:
                    units.append(phase_child)
            continue
        if child.name == "phase88":
            for phase_child in sorted(child.iterdir()):
                if phase_child.name != "iso":
                    units.append(phase_child)
                    continue
                for iso_child in sorted(phase_child.iterdir()):
                    if iso_child.name == "runs":
                        units.extend(sorted(iso_child.iterdir()))
                    else:
                        units.append(iso_child)
            continue
        if child.name.startswith("phase"):
            units.extend(sorted(child.iterdir()))
            continue
        units.append(child)
    return units


def classify(
    path: Path,
    latest_iso: Path | None,
    latest_phase88_iso_run: Path | None = None,
) -> tuple[str, bool, bool, str]:
    relative = path.relative_to(STATE_ROOT)
    first, name = relative.parts[0], relative.name
    if first in SIMPLE_PRESERVE:
        return "PRESERVE", False, True, "authoritative trust, provenance, or native build state"
    if first == "reconstructed":
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "reconstructable repository proof"
    if first == "tmp" or name == "tmp":
        return "FAILED_OR_SCRATCH", True, False, "managed temporary workspace"
    if first == "phase4" and len(relative.parts) >= 3 and relative.parts[1] == "out":
        if latest_iso is not None and path.resolve() == latest_iso.resolve():
            return "PRESERVE_LATEST", True, True, "latest qualified ISO named by current media report"
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "superseded reproducible ISO output"
    if name.startswith("failed-") or name in {
        "pilot-rootfs", "experiment-root", "experiment-root2", "debug", "debug2",
        "input-verification", "fetch-scratch", "publish-scratch",
    }:
        return "FAILED_OR_SCRATCH", True, False, "failed, experimental, or verification scratch"
    if first in PHASE_PRESERVE and name in PHASE_PRESERVE[first]:
        return "PRESERVE", False, True, "required canonical input, trust state, or regression artifact"
    if first == "phase4" and name == "cache":
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "optional package cache"
    if first == "phase4" and name in {"runs", "staged", "work"}:
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "completed media or acceptance workspace"
    if first == "phase88" and len(relative.parts) >= 3 and relative.parts[1] == "iso":
        if relative.parts[2] == "artifacts":
            return "PRESERVE", False, True, "current Phase 8.8 ISO acceptance report"
        if relative.parts[2] == "runs":
            if latest_phase88_iso_run is not None and path.resolve() == latest_phase88_iso_run.resolve():
                return "PRESERVE", True, True, "latest qualified Phase 8.8 ISO evidence"
            report = path / "phase4-acceptance.json"
            category = "EVIDENCE_RECORDED_REBUILDABLE" if report.is_file() else "FAILED_OR_SCRATCH"
            return category, True, False, "superseded or failed Phase 8.8 ISO acceptance run"
    if first == "phase88" and name.startswith("static-"):
        expected = f"static-{latest_iso.name[:7]}" if latest_iso is not None else None
        if name == expected:
            return "PRESERVE", True, True, "static validation for the latest qualified ISO"
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "superseded static media extraction"
    if first == "phase88" and name in {
        "diagnostic", "input-g0004-verify", "rescue-diagnostic",
    }:
        return "FAILED_OR_SCRATCH", True, False, "Phase 8.8 diagnostic or verification scratch"
    if first == "phase3" and name in {"runs", "work"}:
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "completed install-engine workspace"
    if first == "phase5" and name.startswith("qualification-"):
        category = "FAILED_OR_SCRATCH" if name == "qualification-2c19fd7" else "EVIDENCE_RECORDED_REBUILDABLE"
        return category, True, False, "tracked qualification summary preserves the result"
    if first == "phase6" and (name.startswith("qualification") or name == "fetched-g0002"):
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "tracked result and canonical bundle preserve the proof"
    if first == "phase7" and name in {"https-fetch-scratch", "https-retrieved-g0002"}:
        category = "FAILED_OR_SCRATCH" if name == "https-fetch-scratch" else "EVIDENCE_RECORDED_REBUILDABLE"
        return category, True, False, "duplicate authenticated retrieval state"
    if first == "phase8" and (name == "runs" or name.startswith("static-media-")):
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "tracked Phase 8 summary preserves qualification"
    if first in {"phase81", "phase82", "phase83", "phase84", "phase85"} and name in {
        "runs", "iso", "rescue",
    }:
        return "EVIDENCE_RECORDED_REBUILDABLE", True, False, "tracked phase summary preserves qualification"
    return "UNKNOWN", False, False, "no retention rule matched"


def _references(relative: str) -> list[str]:
    completed = subprocess.run(
        ["git", "grep", "-l", "-F", relative, "--", "."], cwd=PROJECT_ROOT,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return sorted(line for line in completed.stdout.splitlines() if line)


def build_inventory() -> dict[str, Any]:
    latest_iso = _latest_iso_root()
    latest_phase88_iso_run = _latest_phase88_iso_run()
    entries: list[dict[str, Any]] = []
    totals = {category: {"path_count": 0, "disk_usage_bytes": 0} for category in sorted(CATEGORIES)}
    for path in inventory_units():
        category, reproducible, required, reason = classify(
            path, latest_iso, latest_phase88_iso_run
        )
        relative = path.relative_to(PROJECT_ROOT).as_posix()
        disk_usage = _du(path)
        entry = {
            "path": relative,
            "disk_usage_bytes": disk_usage,
            "apparent_size_bytes": _du(path, apparent=True),
            "modified_at": _utc(path.lstat().st_mtime),
            "phase": _phase(path.relative_to(STATE_ROOT)),
            "artifact_type": _artifact_type(path.relative_to(STATE_ROOT)),
            "referenced_by_tracked_files": _references(relative),
            "reproducible": reproducible,
            "required_by_current_regressions": required,
            "classification": category,
            "reason": reason,
        }
        entries.append(entry)
        totals[category]["path_count"] += 1
        totals[category]["disk_usage_bytes"] += disk_usage
    return {
        "schema_version": 1,
        "kind": "kitpro-state-retention-inventory",
        "created_at": _utc(dt.datetime.now().timestamp()),
        "state_root": ".state",
        "latest_qualified_iso_root": (
            latest_iso.relative_to(PROJECT_ROOT).as_posix() if latest_iso else None
        ),
        "entries": entries,
        "totals": totals,
        "delete_path_count": sum(
            totals[name]["path_count"]
            for name in ("EVIDENCE_RECORDED_REBUILDABLE", "FAILED_OR_SCRATCH")
        ),
        "delete_disk_usage_bytes": sum(
            totals[name]["disk_usage_bytes"]
            for name in ("EVIDENCE_RECORDED_REBUILDABLE", "FAILED_OR_SCRATCH")
        ),
    }


def capacity_report(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    probe = resolved
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = shutil.disk_usage(probe)
    status = "qualified" if usage.free >= RECOMMENDED_BYTES else "degraded"
    if usage.free < HARD_MINIMUM_BYTES:
        status = "blocked"
    return {
        "path": str(resolved),
        "filesystem_probe": str(probe),
        "free_bytes": usage.free,
        "hard_minimum_bytes": HARD_MINIMUM_BYTES,
        "recommended_bytes": RECOMMENDED_BYTES,
        "status": status,
    }


def require_heavy_capacity(path: Path) -> dict[str, Any]:
    report = capacity_report(path)
    if report["status"] == "blocked":
        raise kitpro_repo.PipelineError(
            "insufficient storage for heavy work: "
            f"{report['free_bytes']} bytes free; hard minimum is {HARD_MINIMUM_BYTES} bytes "
            f"and recommended capacity is {RECOMMENDED_BYTES} bytes"
        )
    return report


def configure_managed_tmpdir(state_root: Path) -> Path:
    temporary = state_root / "tmp"
    temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary.chmod(0o700)
    os.environ["TMPDIR"] = str(temporary.resolve())
    tempfile.tempdir = str(temporary.resolve())
    return temporary


def prepare_heavy_work(state_root: Path) -> dict[str, Any]:
    """Validate capacity and keep large temporary files on managed storage."""
    report = require_heavy_capacity(state_root)
    report["tmpdir"] = str(configure_managed_tmpdir(state_root))
    return report


def cleanup_success_artifacts(run_root: Path, *, keep_artifacts: bool = False) -> list[str]:
    if keep_artifacts:
        return []
    resolved = run_root.resolve()
    state = STATE_ROOT.resolve()
    if resolved == state or state not in resolved.parents or not resolved.is_dir() or resolved.is_symlink():
        raise kitpro_repo.PipelineError(f"refusing unsafe successful-run cleanup target: {resolved}")
    removed: list[str] = []
    for path in sorted(resolved.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        disposable = (
            path.suffix in {".raw", ".qcow2"}
            or (path.name.startswith("OVMF_VARS") and path.suffix == ".fd")
            or path.name in {"administrator_ed25519", "phase2_admin_ed25519"}
        )
        if disposable:
            path.unlink()
            removed.append(path.relative_to(PROJECT_ROOT).as_posix())
    return removed


def cleanup_generated_tree(
    path: Path,
    *,
    allowed_root: Path,
    keep_artifacts: bool = False,
) -> bool:
    """Remove one exact generated tree after a successful heavy operation."""
    if keep_artifacts or not path.exists():
        return False
    resolved = path.resolve()
    root = allowed_root.resolve()
    if resolved == root or root not in resolved.parents or path.is_symlink():
        raise kitpro_repo.PipelineError(f"refusing unsafe generated-tree cleanup target: {resolved}")

    _make_tree_writable(resolved)
    shutil.rmtree(path)
    return True


def _make_tree_writable(path: Path) -> None:
    for directory in sorted(
        (item for item in path.rglob("*") if item.is_dir() and not item.is_symlink()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(directory.stat().st_mode | 0o700)
    path.chmod(path.stat().st_mode | 0o700)


def _safe_remove(path: Path) -> None:
    resolved = path.resolve()
    state = STATE_ROOT.resolve()
    if resolved == state or state not in resolved.parents:
        raise kitpro_repo.PipelineError(f"refusing unsafe state cleanup target: {resolved}")
    if path.is_symlink() or path.is_file():
        path.unlink()
        return

    _make_tree_writable(path)
    shutil.rmtree(path)


def prune_inventory(inventory_path: Path, receipt_path: Path) -> dict[str, Any]:
    inventory = kitpro_repo.load_json(inventory_path)
    if inventory.get("kind") != "kitpro-state-retention-inventory":
        raise kitpro_repo.PipelineError("cleanup input is not a state-retention inventory")
    unknown = [entry["path"] for entry in inventory["entries"] if entry["classification"] == "UNKNOWN"]
    if unknown:
        raise kitpro_repo.PipelineError(f"refusing cleanup with unknown entries: {unknown}")
    allowed = {"EVIDENCE_RECORDED_REBUILDABLE", "FAILED_OR_SCRATCH"}
    candidates = [entry for entry in inventory["entries"] if entry["classification"] in allowed]
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "kind": "kitpro-state-cleanup-receipt",
        "started_at": _utc(dt.datetime.now().timestamp()),
        "inventory_path": inventory_path.relative_to(PROJECT_ROOT).as_posix(),
        "inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "status": "running",
        "planned_path_count": len(candidates),
        "planned_disk_usage_bytes": sum(entry["disk_usage_bytes"] for entry in candidates),
        "deleted": [],
        "failed": [],
    }
    kitpro_repo.atomic_write_json(receipt_path, receipt)
    for entry in candidates:
        path = PROJECT_ROOT / entry["path"]
        if not path.exists() and not path.is_symlink():
            receipt["failed"].append({"path": entry["path"], "error": "path disappeared before cleanup"})
            kitpro_repo.atomic_write_json(receipt_path, receipt)
            continue
        try:
            _safe_remove(path)
            receipt["deleted"].append(
                {
                    "path": entry["path"],
                    "disk_usage_bytes": entry["disk_usage_bytes"],
                    "classification": entry["classification"],
                    "reason": entry["reason"],
                }
            )
        except OSError as error:
            receipt["failed"].append({"path": entry["path"], "error": str(error)})
        kitpro_repo.atomic_write_json(receipt_path, receipt)
    receipt["completed_at"] = _utc(dt.datetime.now().timestamp())
    receipt["deleted_path_count"] = len(receipt["deleted"])
    receipt["deleted_disk_usage_bytes"] = sum(
        entry["disk_usage_bytes"] for entry in receipt["deleted"]
    )
    receipt["status"] = "passed" if not receipt["failed"] else "partial"
    kitpro_repo.atomic_write_json(receipt_path, receipt)
    return receipt


def reconcile_inventory(inventory_path: Path, receipt_path: Path) -> dict[str, Any]:
    """Record whether every exact deletion candidate from an inventory is absent."""
    inventory = kitpro_repo.load_json(inventory_path)
    if inventory.get("kind") != "kitpro-state-retention-inventory":
        raise kitpro_repo.PipelineError("cleanup input is not a state-retention inventory")
    allowed = {"EVIDENCE_RECORDED_REBUILDABLE", "FAILED_OR_SCRATCH"}
    candidates = [entry for entry in inventory["entries"] if entry["classification"] in allowed]
    deleted = [
        {
            "path": entry["path"],
            "disk_usage_bytes": entry["disk_usage_bytes"],
            "classification": entry["classification"],
            "reason": entry["reason"],
        }
        for entry in candidates
        if not (PROJECT_ROOT / entry["path"]).exists()
        and not (PROJECT_ROOT / entry["path"]).is_symlink()
    ]
    remaining = [
        entry["path"]
        for entry in candidates
        if (PROJECT_ROOT / entry["path"]).exists()
        or (PROJECT_ROOT / entry["path"]).is_symlink()
    ]
    receipt = {
        "schema_version": 1,
        "kind": "kitpro-state-cleanup-reconciliation",
        "created_at": _utc(dt.datetime.now().timestamp()),
        "inventory_path": inventory_path.relative_to(PROJECT_ROOT).as_posix(),
        "inventory_sha256": hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        "status": "passed" if not remaining else "partial",
        "planned_path_count": len(candidates),
        "planned_disk_usage_bytes": sum(entry["disk_usage_bytes"] for entry in candidates),
        "deleted_path_count": len(deleted),
        "deleted_disk_usage_bytes": sum(entry["disk_usage_bytes"] for entry in deleted),
        "deleted": deleted,
        "remaining": remaining,
    }
    kitpro_repo.atomic_write_json(receipt_path, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--output", type=Path, required=True)
    capacity = commands.add_parser("capacity")
    capacity.add_argument("path", type=Path, nargs="?", default=STATE_ROOT)
    prune = commands.add_parser("prune")
    prune.add_argument("--inventory", type=Path, required=True)
    prune.add_argument("--receipt", type=Path, required=True)
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--inventory", type=Path, required=True)
    reconcile.add_argument("--receipt", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "inventory":
            document = build_inventory()
            kitpro_repo.atomic_write_json(arguments.output, document)
        elif arguments.command == "capacity":
            document = capacity_report(arguments.path)
        elif arguments.command == "prune":
            document = prune_inventory(arguments.inventory.resolve(), arguments.receipt.resolve())
        else:
            document = reconcile_inventory(
                arguments.inventory.resolve(), arguments.receipt.resolve()
            )
        print(json.dumps(document, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, kitpro_repo.PipelineError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
