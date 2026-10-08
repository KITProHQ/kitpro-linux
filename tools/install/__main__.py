"""Command-line installer for KITPro Linux Server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools import kitpro_repo
from tools.install.disk import create_test_disk
from tools.install.engine import apply, validate_report
from tools.install.model import GIB, load_spec
from tools.install.plan import build_plan, load_plan
from tools.install.receipt import load_source_metadata


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    validate = subcommands.add_parser("validate")
    validate.add_argument("spec", type=Path)
    plan = subcommands.add_parser("plan")
    plan.add_argument("spec", type=Path)
    plan.add_argument("--output", type=Path, required=True)
    create = subcommands.add_parser("create-test-disk")
    create.add_argument("target", type=Path)
    create.add_argument("--size-gib", type=int, default=8)
    install = subcommands.add_parser("apply")
    install.add_argument("spec", type=Path)
    install.add_argument("--plan", type=Path, required=True)
    install.add_argument("--allow-disk-erase", action="store_true")
    install.add_argument("--source-metadata", type=Path)
    report = subcommands.add_parser("validate-report")
    report.add_argument("path", type=Path)
    return command


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "validate":
            spec = load_spec(arguments.spec.resolve())
            result = {"result": "valid", "install_spec_sha256": spec.sha256(), "spec": spec.to_dict()}
        elif arguments.command == "plan":
            spec = load_spec(arguments.spec.resolve())
            result = build_plan(spec)
            kitpro_repo.atomic_write_json(arguments.output.resolve(), result)
        elif arguments.command == "create-test-disk":
            result = create_test_disk(arguments.target.resolve(), arguments.size_gib * GIB)
        elif arguments.command == "apply":
            spec = load_spec(arguments.spec.resolve())
            plan = load_plan(arguments.plan.resolve())
            source_metadata = load_source_metadata(
                arguments.source_metadata.resolve() if arguments.source_metadata else None
            )
            report_path, report = apply(
                spec, plan, arguments.allow_disk_erase, source_metadata
            )
            result = {"report_path": str(report_path), "report": report}
        else:
            result = kitpro_repo.load_json(arguments.path.resolve())
            validate_report(result)
            result = {"result": "valid", "report": result}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (kitpro_repo.PipelineError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
