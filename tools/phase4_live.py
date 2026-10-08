#!/usr/bin/env python3
"""Runtime preparation and installation-result checks for KITPro media."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from tools import kitpro_phase2, kitpro_repo
from tools.install.engine import validate_report
from tools.install.receipt import load_source_metadata


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = Path("/run/kitpro-install")
SPEC_PATH = RUNTIME_ROOT / "install-spec.json"
PLAN_PATH = RUNTIME_ROOT / "install-plan.json"


def _block_inventory() -> list[dict[str, Any]]:
    completed = subprocess.run(
        ["lsblk", "-J", "-d", "-o", "PATH,TYPE"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise kitpro_repo.PipelineError(f"cannot enumerate installation devices: {completed.stderr.strip()}")
    devices = json.loads(completed.stdout).get("blockdevices", [])
    if not isinstance(devices, list):
        raise kitpro_repo.PipelineError("lsblk returned an invalid device inventory")
    return devices


def prepare() -> dict[str, Any]:
    source = load_source_metadata(PROJECT_ROOT / "media/source-metadata.json")
    if source.get("repository_release") == "1.0":
        from tools.install import production
        from tools.production_repository import production_pacman_config
        production.prepare_trust(source["repository_generation"], PROJECT_ROOT / "repo")
        if Path("/etc/pacman.conf").read_text() != production_pacman_config():
            raise kitpro_repo.PipelineError("live production repository policy differs")
        repositories = ["kitpro-1.0-core"]
    else:
        public = PROJECT_ROOT / ".state/dev-keys/public"
        for role in ("package", "repository"):
            kitpro_repo.setup_kitpro_keyring(PROJECT_ROOT / ".state/dev-keys" / role, public)
        kitpro_repo.setup_kitpro_keyring(PROJECT_ROOT / ".state/client/gnupg", public)
        repositories = kitpro_phase2.validate_repository_isolation(Path("/etc/pacman.conf"))

    result: dict[str, Any] = {
        "source": source,
        "repositories": repositories,
        "keyrings": "public-only",
    }
    if SPEC_PATH.is_file():
        specification = kitpro_repo.load_json(SPEC_PATH)
        disk = specification.get("disk", {})
        if disk.get("device") != "/dev/vda" or disk.get("target_type") != "block":
            raise kitpro_repo.PipelineError(
                "media acceptance permits only the explicit /dev/vda block target"
            )
        inventory = _block_inventory()
        disks = sorted(item.get("path") for item in inventory if item.get("type") == "disk")
        optical = sorted(item.get("path") for item in inventory if item.get("type") == "rom")
        if disks != ["/dev/vda"] or "/dev/sr0" not in optical:
            raise kitpro_repo.PipelineError(
                f"unexpected acceptance device inventory: disks={disks}, optical={optical}"
            )
        result["target"] = "/dev/vda"
        result["device_inventory"] = inventory
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(RUNTIME_ROOT / "runtime-preparation.json", result)
    return result


def verify_result() -> dict[str, Any]:
    plan = kitpro_repo.load_json(PLAN_PATH)
    report_path = (
        PROJECT_ROOT / ".state/phase3/evidence" / plan["plan_sha256"] / "installation-report.json"
    )
    report = kitpro_repo.load_json(report_path)
    validate_report(report)
    if report["result"] != "installed_pending_first_boot":
        raise kitpro_repo.PipelineError("media installation did not reach pending-first-boot state")
    result = {
        "schema_version": 1,
        "status": "installed_pending_first_boot",
        "plan_sha256": plan["plan_sha256"],
        "installation_report": str(report_path),
        "installation_report_sha256": kitpro_repo.sha256_file(report_path),
        "target": report["target"],
        "repository_generation": report["repository_generation"],
        "install_receipt": report["install_receipt"],
    }
    kitpro_repo.atomic_write_json(RUNTIME_ROOT / "media-install-result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify-result"))
    arguments = parser.parse_args()
    try:
        result = prepare() if arguments.command == "prepare" else verify_result()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError, ValueError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
