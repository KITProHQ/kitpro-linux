"""Plan and validate a non-executable KITPro Linux 1.0 to 1.1 transition."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from tools import kitpro_repo, release_foundation, release_generation_candidate

PLAN_KIND = "kitpro-linux-release-transition-plan"
CHECKPOINT_STATES = (
    "planned",
    "artifacts-verified",
    "packages-applied",
    "boot-pending",
    "complete",
)


def _version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)(?:\.([0-9]+))?", value)
    if not match:
        raise ValueError(f"invalid release version: {value}")
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def _generation(value: str) -> tuple[tuple[int, int, int], int]:
    match = re.fullmatch(r"([0-9]+\.[0-9]+)-g([0-9]{4})", value)
    if not match:
        raise ValueError(f"invalid generation identity: {value}")
    return _version(match.group(1)), int(match.group(2))


def required_approval(current_release: str, target_generation: str) -> str:
    return f"UPGRADE KITPro Linux Server {current_release} TO {target_generation}"


def plan(
    current: dict[str, Any],
    foundation: dict[str, Any],
    *,
    target_kernel: str,
    approval: str,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a validated development plan without exposing an execution operation."""
    release_foundation.validate(foundation)
    if current.get("release") != "1.0" or current.get("generation") != "1.0-g0002":
        raise ValueError("only the qualified 1.0-g0002 predecessor is supported")
    current_manifest_sha = current.get("generation_manifest_sha256")
    if current_manifest_sha != foundation["predecessor"]["manifest_sha256"]:
        raise ValueError("installed generation identity does not match the foundation predecessor")
    target_release = foundation["repository"]["release"]
    target_generation = foundation["repository"]["generation"]
    if _version(target_release) <= _version(current["release"]):
        raise ValueError("target release is not newer than the installed release")
    if _generation(target_generation)[0] != _version(target_release):
        raise ValueError("target generation does not belong to the target release")
    expected_approval = required_approval(current["release"], target_generation)
    if approval != expected_approval:
        raise ValueError("explicit administrator approval does not match the transition")
    if not isinstance(target_kernel, str) or not target_kernel:
        raise ValueError("target kernel identity is required")

    candidate_sha256 = None
    if candidate is not None:
        release_generation_candidate.validate(candidate)
        if candidate["foundation_sha256"] != release_foundation.digest(foundation):
            raise ValueError("generation candidate does not belong to this foundation")
        if candidate["kernel"]["candidate"]["version"] != target_kernel:
            raise ValueError("target kernel does not match the generation candidate")
        candidate_sha256 = release_generation_candidate.digest(candidate)

    default_packages = foundation["default_install"]["packages"]
    default_names = {package["name"] for package in default_packages}
    optional_names = {
        package["name"]
        for package in foundation["optional_components"]["console"]["candidate_packages"]
    }
    if default_names & optional_names:
        raise ValueError("optional Console packages cannot enter the default transition closure")
    if "linux-lts" not in default_names:
        raise ValueError("default transition closure is missing linux-lts")

    current_kernel = current.get("kernel")
    kernel_changed = current_kernel != target_kernel
    document = {
        "schema_version": 1,
        "kind": PLAN_KIND,
        "status": "validated-development-plan",
        "current": {
            "release": current["release"],
            "generation": current["generation"],
            "generation_manifest_sha256": current_manifest_sha,
            "kernel": current_kernel,
        },
        "target": {
            "release": target_release,
            "generation": target_generation,
            "foundation_sha256": release_foundation.digest(foundation),
            "artifact_state": foundation["artifact_state"],
            "candidate_sha256": candidate_sha256,
        },
        "trust": {
            "repository_signature_required": True,
            "database_signature_required": True,
            "trusted_only": True,
            "repository_fingerprint": foundation["trust"]["repository_fingerprint"],
            "development_keys_allowed": False,
            "target_signatures_available": False,
        },
        "packages": {
            "closure": "default-core-only",
            "package_count": len(default_packages),
            "optional_components_selected": [],
            "console_installed": False,
            "native_identity_packages": (
                "built-unsigned" if candidate is not None else "pending-1.1-build"
            ),
            "closure_sha256": candidate["core"]["packages_sha256"] if candidate else None,
        },
        "kernel": {
            "current": current_kernel,
            "target": target_kernel,
            "changed": kernel_changed,
            "initramfs_required": True,
            "systemd_boot_required": True,
            "preserve_previous_known_good": kernel_changed,
            "automatic_rollback": False,
        },
        "approval": {
            "required_phrase": expected_approval,
            "matched": True,
        },
        "recovery": {
            "checkpoint_states": list(CHECKPOINT_STATES),
            "resume_automatically": False,
            "interrupted_state_action": "stop-and-inspect",
            "package_downgrade_supported": False,
            "generation_rewind_supported": False,
        },
        "execution": {
            "enabled": False,
            "reason": "target artifacts are unsigned development inputs",
        },
    }
    validate(document)
    return document


def validate(document: dict[str, Any]) -> None:
    if document.get("schema_version") != 1 or document.get("kind") != PLAN_KIND:
        raise ValueError("unsupported release transition plan")
    if document.get("status") != "validated-development-plan":
        raise ValueError("transition plan is not development-only")
    current = document.get("current", {})
    target = document.get("target", {})
    if _version(target.get("release", "")) <= _version(current.get("release", "")):
        raise ValueError("downgrade or same-release transition is forbidden")
    if _generation(target.get("generation", ""))[0] != _version(target["release"]):
        raise ValueError("target generation/release mismatch")
    trust = document.get("trust", {})
    if not all(
        trust.get(field) is True
        for field in (
            "repository_signature_required",
            "database_signature_required",
            "trusted_only",
        )
    ):
        raise ValueError("signature enforcement cannot be weakened")
    if trust.get("development_keys_allowed") is not False:
        raise ValueError("development signing keys cannot authorize the transition")
    if document.get("packages", {}).get("optional_components_selected") != []:
        raise ValueError("default transition unexpectedly selected an optional component")
    candidate_sha = target.get("candidate_sha256")
    if candidate_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", candidate_sha):
        raise ValueError("target candidate binding is invalid")
    kernel = document.get("kernel", {})
    if (
        kernel.get("initramfs_required") is not True
        or kernel.get("systemd_boot_required") is not True
    ):
        raise ValueError("kernel boot artifacts are required")
    if kernel.get("changed") is True and kernel.get("preserve_previous_known_good") is not True:
        raise ValueError("changed kernel must preserve the previous known-good kernel")
    recovery = document.get("recovery", {})
    if recovery.get("checkpoint_states") != list(CHECKPOINT_STATES):
        raise ValueError("transition recovery state machine changed")
    if recovery.get("resume_automatically") is not False:
        raise ValueError("interrupted transitions must stop for inspection")
    if recovery.get("generation_rewind_supported") is not False:
        raise ValueError("generation rewind is forbidden")
    if document.get("approval", {}).get("matched") is not True:
        raise ValueError("administrator approval is missing")
    if document.get("execution") != {
        "enabled": False,
        "reason": "target artifacts are unsigned development inputs",
    }:
        raise ValueError("development transition plan must remain non-executable")


def assess_checkpoint(plan_document: dict[str, Any], checkpoint: dict[str, Any]) -> dict[str, str]:
    """Classify an interrupted transition without resuming or mutating it."""
    validate(plan_document)
    expected_digest = kitpro_repo.sha256_bytes(kitpro_repo.canonical_json_bytes(plan_document))
    if checkpoint.get("plan_sha256") != expected_digest:
        raise ValueError("checkpoint does not belong to the approved transition plan")
    state = checkpoint.get("state")
    if state not in CHECKPOINT_STATES:
        raise ValueError("unsupported transition checkpoint state")
    if state == "complete":
        return {"classification": "complete", "action": "verify-installed-identity"}
    if state in {"packages-applied", "boot-pending"}:
        return {
            "classification": "interrupted-after-package-change",
            "action": "boot-recovery-inspection",
        }
    return {
        "classification": "interrupted-before-package-change",
        "action": "discard-plan-and-replan",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", type=Path)
    parser.add_argument("--config", type=Path, default=release_foundation.CONFIG_PATH)
    parser.add_argument("--target-kernel", required=True)
    parser.add_argument("--approve", required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    current = kitpro_repo.load_json(arguments.current)
    foundation = release_foundation.build(arguments.config)
    document = plan(
        current,
        foundation,
        target_kernel=arguments.target_kernel,
        approval=arguments.approve,
        candidate=kitpro_repo.load_json(arguments.candidate) if arguments.candidate else None,
    )
    if arguments.output:
        kitpro_repo.atomic_write_json(arguments.output, document)
    else:
        print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
