#!/usr/bin/env python3
"""Release-aware validation and local staging for production repositories.

The module has no signing or remote-publication operation. Immutable generation
placement and release-scoped ``current`` promotion are separate operations.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools import kitpro_repo

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_BASE_URL = "https://repo.kitpro.us/kitpro-linux"
ARCH = "x86_64"
PACKAGE_FINGERPRINT = "4742B8D5550858F1723C8E0DB0DCE551DDD9F456"
REPOSITORY_FINGERPRINT = "52BADA3613798054B7E35840DC088D21DA29F538"
ROOT_FINGERPRINT = "913BDB5D1E06A5B57F46F5B674DAF522F825A435"

RELEASE_PATTERN = re.compile(r"[0-9]+\.[0-9]+")
FINGERPRINT_PATTERN = re.compile(r"[0-9A-F]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
SAFE_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")
SAFE_PACKAGE_FILENAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]*")

FORBIDDEN_PRODUCTION_MARKERS = (
    "0.1-dev",
    "DEVELOPMENT",
    "KITPro Linux TEST",
    "dev-root@kitpro.invalid",
    "dev-package@kitpro.invalid",
    "dev-repository@kitpro.invalid",
    "kitpro-development-repository-ca",
)

CONSOLE_PACKAGES = (
    "apparmor",
    "containerd",
    "docker",
    "kitpro-server",
    "libpathrs",
    "libtool",
    "mailcap",
    "nginx",
    "python-legacy-cgi",
    "runc",
)


@dataclass(frozen=True)
class RepositoryTrust:
    package_fingerprint: str
    repository_fingerprint: str
    root_fingerprint: str
    signature_level: str = "Required DatabaseRequired TrustedOnly"
    local_file_signature_level: str = "Required TrustedOnly"

    def __post_init__(self) -> None:
        for name, value in (
            ("package", self.package_fingerprint),
            ("repository", self.repository_fingerprint),
            ("root", self.root_fingerprint),
        ):
            if not FINGERPRINT_PATTERN.fullmatch(value):
                raise ValueError(f"invalid {name} trust fingerprint")
        if self.signature_level != "Required DatabaseRequired TrustedOnly":
            raise ValueError("production repository signatures cannot be weakened")
        if self.local_file_signature_level != "Required TrustedOnly":
            raise ValueError("production local package signatures cannot be weakened")


@dataclass(frozen=True)
class ReleaseRepositoryConfig:
    release: str
    canonical_version: str
    repository_name: str
    component: str
    architecture: str
    expected_package_count: int
    expected_explicit_package_count: int
    trust: RepositoryTrust
    forbidden_core_packages: tuple[str, ...] = ()
    require_inventory_metadata: bool = True
    base_url: str = PRODUCTION_BASE_URL

    def __post_init__(self) -> None:
        if not RELEASE_PATTERN.fullmatch(self.release):
            raise ValueError("invalid release identifier")
        if self.canonical_version != f"{self.release}.0":
            raise ValueError("canonical version does not match release")
        if self.repository_name != f"kitpro-{self.release}-core":
            raise ValueError("repository namespace does not match release")
        if self.component != "core" or self.architecture != ARCH:
            raise ValueError("unsupported repository component or architecture")
        if not 1 <= self.expected_explicit_package_count <= self.expected_package_count <= 4096:
            raise ValueError("invalid package closure counts")
        if self.base_url != PRODUCTION_BASE_URL:
            raise ValueError("production repository base URL changed")
        if len(set(self.forbidden_core_packages)) != len(self.forbidden_core_packages):
            raise ValueError("duplicate forbidden core package")
        if any(not SAFE_TOKEN_PATTERN.fullmatch(name) for name in self.forbidden_core_packages):
            raise ValueError("unsafe forbidden core package name")

    @property
    def database_filename(self) -> str:
        return f"{self.repository_name}.db.tar.gz"


PRODUCTION_TRUST = RepositoryTrust(
    package_fingerprint=PACKAGE_FINGERPRINT,
    repository_fingerprint=REPOSITORY_FINGERPRINT,
    root_fingerprint=ROOT_FINGERPRINT,
)

RELEASE_CONFIGS = {
    "1.0": ReleaseRepositoryConfig(
        release="1.0",
        canonical_version="1.0.0",
        repository_name="kitpro-1.0-core",
        component="core",
        architecture=ARCH,
        expected_package_count=199,
        expected_explicit_package_count=36,
        trust=PRODUCTION_TRUST,
        require_inventory_metadata=False,
    ),
    "1.1": ReleaseRepositoryConfig(
        release="1.1",
        canonical_version="1.1.0",
        repository_name="kitpro-1.1-core",
        component="core",
        architecture=ARCH,
        expected_package_count=199,
        expected_explicit_package_count=36,
        trust=PRODUCTION_TRUST,
        forbidden_core_packages=CONSOLE_PACKAGES,
    ),
}


@dataclass(frozen=True)
class PromotionAuthorization:
    release: str
    generation: str
    manifest_sha256: str
    phrase: str

    @classmethod
    def create(
        cls,
        config: ReleaseRepositoryConfig,
        generation: str,
        manifest_sha256: str,
        phrase: str,
    ) -> PromotionAuthorization:
        generation_number(generation, config)
        if not SHA256_PATTERN.fullmatch(manifest_sha256):
            raise ValueError("promotion manifest SHA-256 is invalid")
        value = cls(config.release, generation, manifest_sha256, phrase)
        value.validate(config)
        return value

    def validate(self, config: ReleaseRepositoryConfig) -> None:
        if self.release != config.release:
            raise kitpro_repo.PipelineError("promotion authorization release mismatch")
        generation_number(self.generation, config)
        if not SHA256_PATTERN.fullmatch(self.manifest_sha256):
            raise kitpro_repo.PipelineError("promotion authorization manifest hash is invalid")
        if self.phrase != promotion_phrase(config, self.generation):
            raise kitpro_repo.PipelineError("current-pointer promotion is not authorized")


def release_config(release: str) -> ReleaseRepositoryConfig:
    if not RELEASE_PATTERN.fullmatch(release):
        raise kitpro_repo.PipelineError(f"invalid production release: {release}")
    try:
        return RELEASE_CONFIGS[release]
    except KeyError as error:
        raise kitpro_repo.PipelineError(f"unsupported production release: {release}") from error


def generation_number(generation: str, config: ReleaseRepositoryConfig) -> int:
    match = re.fullmatch(rf"{re.escape(config.release)}-g([0-9]{{4}})", generation)
    if not match:
        raise kitpro_repo.PipelineError(
            f"invalid {config.release} production generation: {generation}"
        )
    return int(match.group(1))


def generation_path(generation: str, config: ReleaseRepositoryConfig) -> str:
    generation_number(generation, config)
    return f"stable/{config.release}/{generation}/{config.component}/os/$arch"


def production_pacman_config(config: ReleaseRepositoryConfig) -> str:
    return (
        "[options]\n"
        "HoldPkg = pacman glibc\n"
        "Architecture = auto\n"
        "CheckSpace\n"
        "ParallelDownloads = 5\n"
        "DownloadUser = alpm\n"
        f"SigLevel = {config.trust.signature_level}\n"
        f"LocalFileSigLevel = {config.trust.local_file_signature_level}\n\n"
        f"[{config.repository_name}]\n"
        f"SigLevel = {config.trust.signature_level}\n"
        f"Server = {config.base_url}/stable/{config.release}/current/"
        f"{config.component}/os/$arch\n"
    )


def promotion_phrase(config: ReleaseRepositoryConfig, generation: str) -> str:
    generation_number(generation, config)
    return f"PROMOTE KITPRO REPOSITORY stable/{config.release}/current TO {generation}"


def _safe_basename(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or Path(value).name != value
        or not SAFE_TOKEN_PATTERN.fullmatch(value)
    ):
        raise kitpro_repo.PipelineError(f"unsafe {field}")
    return value


def _safe_package_filename(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or Path(value).name != value
        or not SAFE_PACKAGE_FILENAME_PATTERN.fullmatch(value)
    ):
        raise kitpro_repo.PipelineError(f"unsafe {field}")
    return value


def _safe_path(root: Path, *parts: str) -> Path:
    for part in parts:
        _safe_basename(part, "repository path component")
    root_resolved = root.resolve()
    candidate = root.joinpath(*parts)
    resolved = candidate.resolve(strict=False)
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise kitpro_repo.PipelineError("repository path escapes the publication root")
    return candidate


def _private_infrastructure_markers(text: str) -> list[str]:
    patterns = {
        "internal-hostname": r"(?i)(?:[a-z0-9_-]+\.)+(?:home|internal|local)\.[a-z0-9.-]+",
        "private-ipv4": (
            r"(?<![\w.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\w.])"
        ),
        "operator-home-path": r"/(?:home|Users)/[a-zA-Z_][a-zA-Z0-9_-]*(?:/|\b)",
    }
    return [name for name, pattern in patterns.items() if re.search(pattern, text)]


def contamination_findings(root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_dir() or path.is_symlink():
            continue
        try:
            text = path.read_text(errors="ignore")
        except OSError as error:
            findings.append(
                {"path": path.relative_to(root).as_posix(), "marker": f"unreadable: {error}"}
            )
            continue
        for marker in _private_infrastructure_markers(text):
            findings.append({"path": path.relative_to(root).as_posix(), "marker": marker})
        for marker in FORBIDDEN_PRODUCTION_MARKERS:
            if marker in text:
                findings.append({"path": path.relative_to(root).as_posix(), "marker": marker})
    return findings


def _copy_immutable_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    for item in sorted(source.rglob("*"), key=lambda path: path.as_posix()):
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_symlink():
            raise kitpro_repo.PipelineError(f"generation contains symlink: {relative}")
        if item.is_dir():
            target.mkdir(parents=True, mode=0o700, exist_ok=True)
            continue
        if not item.is_file():
            raise kitpro_repo.PipelineError(f"generation contains unsafe entry: {relative}")
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        shutil.copyfile(item, target)
        os.chmod(target, 0o444)
    for directory in sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        os.chmod(directory, 0o555)
    os.chmod(destination, 0o555)


def _file_sha(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise kitpro_repo.PipelineError(f"required regular file is missing: {path}")
    return kitpro_repo.sha256_file(path)


def _database_package_names(database: Path) -> set[str]:
    try:
        with tarfile.open(database, "r:*") as archive:
            names: set[str] = set()
            for member in archive.getmembers():
                if not member.isfile() or not member.name.endswith("/desc"):
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise kitpro_repo.PipelineError("repository database contains unreadable entry")
                fields = {}
                for section in extracted.read().decode().strip().split("\n\n"):
                    lines = section.splitlines()
                    if lines and lines[0].startswith("%"):
                        fields[lines[0].strip("%")] = lines[1:]
                if "NAME" not in fields or len(fields["NAME"]) != 1:
                    raise kitpro_repo.PipelineError("repository database package name is invalid")
                name = fields["NAME"][0]
                if name in names:
                    raise kitpro_repo.PipelineError(
                        "repository database contains duplicate package"
                    )
                names.add(name)
    except (tarfile.TarError, UnicodeDecodeError) as error:
        raise kitpro_repo.PipelineError(
            "repository database is not a valid package archive"
        ) from error
    if not names:
        raise kitpro_repo.PipelineError("repository database package inventory is empty")
    return names


def _validate_source(source: object) -> None:
    if not isinstance(source, dict) or set(source) != {"commit", "tree", "worker_lock"}:
        raise kitpro_repo.PipelineError("production generation source binding is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
        raise kitpro_repo.PipelineError("production source commit is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", source["tree"]):
        raise kitpro_repo.PipelineError("production source tree is invalid")
    if not SHA256_PATTERN.fullmatch(source["worker_lock"]):
        raise kitpro_repo.PipelineError("production worker lock is invalid")


def validate_generation_tree(
    generation_root: Path,
    config: ReleaseRepositoryConfig,
    *,
    qualification_only: bool = False,
) -> dict[str, Any]:
    manifest_path = generation_root / "manifest.json"
    manifest = kitpro_repo.load_json(manifest_path)
    required = {
        "schema_version",
        "release",
        "generation_id",
        "previous_generation",
        "source",
        "repositories",
        "signing_fingerprints",
        "qualification_ids",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise kitpro_repo.PipelineError("production generation manifest fields are invalid")
    if manifest["schema_version"] != 1 or manifest["release"] != config.release:
        raise kitpro_repo.PipelineError("production generation manifest has wrong release")
    generation = manifest["generation_id"]
    number = generation_number(generation, config)
    if generation_root.name != generation:
        raise kitpro_repo.PipelineError("generation path and manifest identity differ")
    previous = manifest["previous_generation"]
    if previous is None:
        if number != 1:
            raise kitpro_repo.PipelineError("non-initial generation lacks a predecessor")
    elif generation_number(previous, config) >= number:
        raise kitpro_repo.PipelineError("generation predecessor is not earlier in the same release")
    _validate_source(manifest["source"])

    fingerprints = manifest["signing_fingerprints"]
    if fingerprints != {
        "package": config.trust.package_fingerprint,
        "repository": config.trust.repository_fingerprint,
    }:
        raise kitpro_repo.PipelineError(
            "production generation trust roots differ from release policy"
        )
    qualification_ids = manifest["qualification_ids"]
    if (
        not isinstance(qualification_ids, list)
        or not qualification_ids
        or any(not isinstance(value, str) or not value for value in qualification_ids)
    ):
        raise kitpro_repo.PipelineError("production qualification identity is missing")
    if qualification_only:
        if config.trust == PRODUCTION_TRUST:
            raise kitpro_repo.PipelineError(
                "qualification validation requires isolated non-production trust"
            )
        production_fingerprints = {
            PRODUCTION_TRUST.package_fingerprint,
            PRODUCTION_TRUST.repository_fingerprint,
            PRODUCTION_TRUST.root_fingerprint,
        }
        qualification_fingerprints = {
            config.trust.package_fingerprint,
            config.trust.repository_fingerprint,
            config.trust.root_fingerprint,
        }
        if production_fingerprints & qualification_fingerprints:
            raise kitpro_repo.PipelineError("qualification trust overlaps production trust")
        if any(not value.startswith("qualification:") for value in qualification_ids):
            raise kitpro_repo.PipelineError(
                "qualification generation identity is not visibly test-only"
            )

    repositories = manifest["repositories"]
    if not isinstance(repositories, list) or len(repositories) != 1:
        raise kitpro_repo.PipelineError("production generation must contain exactly one repository")
    repository = repositories[0]
    if (
        not isinstance(repository, dict)
        or repository.get("name") != config.repository_name
        or repository.get("architecture") != config.architecture
    ):
        raise kitpro_repo.PipelineError("repository namespace does not match release policy")
    database = repository.get("database", {})
    packages = repository.get("packages", [])
    if not isinstance(packages, list) or len(packages) != config.expected_package_count:
        raise kitpro_repo.PipelineError(
            "production package inventory count differs from release policy"
        )

    repo_dir = generation_root / config.component / "os" / config.architecture
    database_name = _safe_basename(database.get("filename"), "repository database filename")
    database_signature = _safe_basename(
        database.get("signature_filename"), "repository database signature filename"
    )
    if (
        database_name != config.database_filename
        or database_signature != f"{config.database_filename}.sig"
    ):
        raise kitpro_repo.PipelineError(
            "repository database identity does not match release policy"
        )
    database_path = repo_dir / database_name
    if _file_sha(database_path) != database.get("sha256"):
        raise kitpro_repo.PipelineError("repository database hash mismatch")
    if _file_sha(repo_dir / database_signature) != database.get("signature_sha256"):
        raise kitpro_repo.PipelineError("repository database signature hash mismatch")
    if database.get("signer_fingerprint") != config.trust.repository_fingerprint:
        raise kitpro_repo.PipelineError("repository database signer differs from release policy")

    package_names: set[str] = set()
    explicit_count = 0
    for package in packages:
        if not isinstance(package, dict):
            raise kitpro_repo.PipelineError("production package record is invalid")
        filename = _safe_package_filename(package.get("filename"), "package filename")
        signature_name = _safe_package_filename(
            package.get("signature_filename"), "package signature filename"
        )
        if signature_name != f"{filename}.sig":
            raise kitpro_repo.PipelineError("package signature filename does not match package")
        if _file_sha(repo_dir / filename) != package.get("sha256"):
            raise kitpro_repo.PipelineError(f"package hash mismatch: {filename}")
        if _file_sha(repo_dir / signature_name) != package.get("signature_sha256"):
            raise kitpro_repo.PipelineError(f"package signature hash mismatch: {signature_name}")
        if package.get("signer_fingerprint") != config.trust.package_fingerprint:
            raise kitpro_repo.PipelineError(f"package signer differs: {filename}")
        name = package.get("name")
        explicit = package.get("explicit")
        if name is None and not config.require_inventory_metadata:
            continue
        if not isinstance(name, str) or not SAFE_TOKEN_PATTERN.fullmatch(name):
            raise kitpro_repo.PipelineError("package inventory name is invalid")
        if name in package_names:
            raise kitpro_repo.PipelineError("package inventory contains duplicate name")
        if not isinstance(explicit, bool):
            raise kitpro_repo.PipelineError("package explicit-install state is invalid")
        package_names.add(name)
        explicit_count += explicit

    if package_names:
        if len(package_names) != config.expected_package_count:
            raise kitpro_repo.PipelineError("package inventory metadata is incomplete")
        if explicit_count != config.expected_explicit_package_count:
            raise kitpro_repo.PipelineError(
                "explicit package inventory count differs from release policy"
            )
        forbidden = package_names & set(config.forbidden_core_packages)
        if forbidden:
            raise kitpro_repo.PipelineError(
                f"optional package leaked into core closure: {sorted(forbidden)}"
            )
        if _database_package_names(database_path) != package_names:
            raise kitpro_repo.PipelineError("repository database inventory differs from manifest")
    elif config.require_inventory_metadata:
        raise kitpro_repo.PipelineError("release requires complete package inventory metadata")

    findings = contamination_findings(generation_root)
    if qualification_only:
        findings = [
            finding for finding in findings if finding["marker"] not in FORBIDDEN_PRODUCTION_MARKERS
        ]
    if findings:
        raise kitpro_repo.PipelineError(
            f"production generation contains development contamination: {findings}"
        )
    return {
        "status": "passed-qualification-only" if qualification_only else "passed",
        "release": config.release,
        "repository": config.repository_name,
        "component": config.component,
        "generation": generation,
        "previous_generation": previous,
        "generation_manifest_sha256": kitpro_repo.sha256_file(manifest_path),
        "repository_db_sha256": database["sha256"],
        "repository_db_signature_sha256": database["signature_sha256"],
        "package_count": len(packages),
        "explicit_package_count": explicit_count if package_names else None,
        "signing_fingerprints": fingerprints,
    }


def stage_qualification_generation(
    source_generation: Path,
    staging_root: Path,
    *,
    config: ReleaseRepositoryConfig,
) -> dict[str, Any]:
    """Immutably stage a test-trust generation without a current pointer."""
    validation = validate_generation_tree(source_generation, config, qualification_only=True)
    generation = validation["generation"]
    release_root = _safe_path(staging_root, "stable", config.release)
    final = _safe_path(staging_root, "stable", config.release, generation)
    if final.exists() or final.is_symlink():
        raise kitpro_repo.PipelineError(f"qualification generation already exists: {generation}")
    release_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{generation}.", dir=release_root))
    try:
        staged_generation = temporary / generation
        _copy_immutable_tree(source_generation, staged_generation)
        staged_validation = validate_generation_tree(
            staged_generation, config, qualification_only=True
        )
        if staged_validation != validation:
            raise kitpro_repo.PipelineError("staged qualification generation differs from source")
        os.chmod(staged_generation, 0o755)
        os.replace(staged_generation, final)
        os.chmod(final, 0o555)
    finally:
        if temporary.exists():
            for path in sorted(
                temporary.rglob("*"), key=lambda item: len(item.parts), reverse=True
            ):
                if path.is_dir() and not path.is_symlink():
                    os.chmod(path, 0o700)
            shutil.rmtree(temporary, ignore_errors=True)
    return {
        "status": "qualification-generation-staged-locally",
        "release": config.release,
        "repository": config.repository_name,
        "generation": generation,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "current_created": False,
        "production_publishable": False,
    }


def validate_rc_input(
    manifest_path: Path,
    config: ReleaseRepositoryConfig = RELEASE_CONFIGS["1.1"],
) -> dict[str, Any]:
    """Validate unsigned RC inputs without representing them as publishable."""
    from tools import release_candidate_preparation, release_generation_candidate

    document = kitpro_repo.load_json(manifest_path)
    release_candidate_preparation.validate(document)
    if document["product"]["canonical_version"] != config.canonical_version:
        raise kitpro_repo.PipelineError("RC product version does not match repository release")
    generation = document["generation"]
    generation_id = generation["proposed"]
    generation_number(generation_id, config)
    if (
        generation["core_package_count"] != config.expected_package_count
        or generation["explicit_package_count"] != config.expected_explicit_package_count
    ):
        raise kitpro_repo.PipelineError("RC core closure counts differ from repository policy")
    console = document["console"]
    if console["installed_by_default"] is not False or console["enabled_by_default"] is not False:
        raise kitpro_repo.PipelineError("Console is not separated from the default core closure")
    kernel = document["kernel"]
    if kernel["package"] != "linux-lts" or kernel["version"] != "6.18.59-1":
        raise kitpro_repo.PipelineError("RC kernel identity differs from the qualified candidate")
    identity = document["release_identity"]
    if (
        identity["package"] != "kitpro-linux-release"
        or identity["state"] != "development-unsigned-not-production-active"
    ):
        raise kitpro_repo.PipelineError("RC native release identity state is invalid")
    trust = document["trust"]
    if (
        trust["production_repository_fingerprint"] != config.trust.repository_fingerprint
        or trust["signature_level"] != config.trust.signature_level
        or trust["local_file_signature_level"] != config.trust.local_file_signature_level
        or any(
            trust[field] is not False
            for field in (
                "production_signatures_complete",
                "repository_database_signed",
                "signed_media_built",
            )
        )
    ):
        raise kitpro_repo.PipelineError("RC trust state differs from unsigned release policy")
    if any(document["authorization"].values()):
        raise kitpro_repo.PipelineError("unsigned RC input authorizes a production action")
    upgrade = document["upgrade"]
    if (
        upgrade["target_generation"] != generation_id
        or upgrade["strict_signatures_required"] is not True
        or upgrade["execution_qualified"] is not False
    ):
        raise kitpro_repo.PipelineError("RC upgrade planner binding is incompatible")

    candidate_relative = Path(generation["candidate_record"])
    if candidate_relative.is_absolute() or ".." in candidate_relative.parts:
        raise kitpro_repo.PipelineError("RC generation candidate path is unsafe")
    candidate_path = PROJECT_ROOT / candidate_relative
    if _file_sha(candidate_path) != generation["candidate_record_sha256"]:
        raise kitpro_repo.PipelineError("RC generation candidate hash changed")
    candidate = kitpro_repo.load_json(candidate_path)
    release_generation_candidate.validate(candidate)
    core = candidate["core"]
    optional = candidate["optional_components"]["console"]
    core_names = {package["name"] for package in core["packages"]}
    optional_names = {package["name"] for package in optional["packages"]}
    if core_names & optional_names or optional_names != set(config.forbidden_core_packages):
        raise kitpro_repo.PipelineError("RC optional Console inventory separation changed")
    if (
        core["packages_sha256"] != generation["core_packages_sha256"]
        or optional["packages_sha256"] != generation["optional_console_packages_sha256"]
    ):
        raise kitpro_repo.PipelineError("RC package closure hash changed")

    return {
        "status": "validated-development-inputs-not-production-qualified",
        "release": config.release,
        "canonical_version": config.canonical_version,
        "repository": config.repository_name,
        "generation": generation_id,
        "generation_path": generation_path(generation_id, config),
        "database": config.database_filename,
        "core_package_count": len(core_names),
        "explicit_package_count": sum(package["explicit"] is True for package in core["packages"]),
        "core_packages_sha256": core["packages_sha256"],
        "console_package_count": len(optional_names),
        "console_installed_by_default": False,
        "kernel": kernel,
        "release_identity": identity,
        "upgrade_plan_sha256": upgrade["plan_sha256"],
        "production_signatures_complete": False,
        "publishable": False,
    }


def current_generation(public_root: Path, config: ReleaseRepositoryConfig) -> str | None:
    current = _safe_path(public_root, "stable", config.release, "current")
    if not current.exists() and not current.is_symlink():
        return None
    if not current.is_symlink():
        raise kitpro_repo.PipelineError("current pointer is not a symlink")
    target = os.readlink(current)
    if Path(target).name != target:
        raise kitpro_repo.PipelineError("current pointer target is unsafe")
    generation_number(target, config)
    return target


def publish_immutable_generation(
    source_generation: Path,
    public_root: Path,
    *,
    config: ReleaseRepositoryConfig,
) -> dict[str, Any]:
    """Atomically place a complete immutable generation without moving current."""
    validation = validate_generation_tree(source_generation, config)
    generation = validation["generation"]
    release_root = _safe_path(public_root, "stable", config.release)
    final = _safe_path(public_root, "stable", config.release, generation)
    if final.exists() or final.is_symlink():
        raise kitpro_repo.PipelineError(f"production generation already exists: {generation}")
    release_root.mkdir(parents=True, mode=0o755, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{generation}.", dir=release_root))
    try:
        staged_generation = staging / generation
        _copy_immutable_tree(source_generation, staged_generation)
        staged_validation = validate_generation_tree(staged_generation, config)
        if staged_validation != validation:
            raise kitpro_repo.PipelineError("staged generation validation differs from source")
        os.chmod(staged_generation, 0o755)
        os.replace(staged_generation, final)
        os.chmod(final, 0o555)
    finally:
        if staging.exists():
            for path in sorted(staging.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                if path.is_dir() and not path.is_symlink():
                    os.chmod(path, 0o700)
            shutil.rmtree(staging, ignore_errors=True)
    return {
        "status": "immutable-generation-published-locally",
        "release": config.release,
        "repository": config.repository_name,
        "generation": generation,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "current": current_generation(public_root, config),
        "current_moved": False,
    }


def promote_current(
    public_root: Path,
    authorization: PromotionAuthorization,
    *,
    config: ReleaseRepositoryConfig,
    publisher_identity: str = "dry-run-publisher",
    publication_host_identity: str = "dry-run-public-origin",
) -> dict[str, Any]:
    """Promote an immutable generation after exact explicit authorization."""
    authorization.validate(config)
    generation = authorization.generation
    target = _safe_path(public_root, "stable", config.release, generation)
    validation = validate_generation_tree(target, config)
    if validation["generation_manifest_sha256"] != authorization.manifest_sha256:
        raise kitpro_repo.PipelineError("promotion authorization does not match generation bytes")
    previous = current_generation(public_root, config)
    if previous is not None and generation_number(generation, config) <= generation_number(
        previous, config
    ):
        raise kitpro_repo.PipelineError("refusing to move production current backward or sideways")
    if validation["previous_generation"] != previous:
        raise kitpro_repo.PipelineError("generation predecessor does not match current pointer")

    receipt = {
        "schema_version": 1,
        "timestamp": kitpro_repo.utc_now(),
        "release": config.release,
        "repository_name": config.repository_name,
        "component": config.component,
        "previous_generation": previous,
        "new_generation": generation,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "repository_db_sha256": validation["repository_db_sha256"],
        "repository_db_signature_sha256": validation["repository_db_signature_sha256"],
        "pointer_update_method": "atomic-symlink-replace",
        "validation_result": "passed",
        "publisher_identity": publisher_identity,
        "signing_fingerprints": validation["signing_fingerprints"],
        "publication_host_identity": publication_host_identity,
    }
    receipt_dir = _safe_path(public_root, "publication-receipts", config.release)
    receipt_dir.mkdir(parents=True, mode=0o755, exist_ok=True)
    receipt_path = _safe_path(
        public_root, "publication-receipts", config.release, f"{generation}.json"
    )
    if receipt_path.exists() or receipt_path.is_symlink():
        raise kitpro_repo.PipelineError("publication receipt already exists")
    kitpro_repo.atomic_write_json(receipt_path, receipt)
    os.chmod(receipt_path, 0o444)

    current = _safe_path(public_root, "stable", config.release, "current")
    # This fixed internal name is derived from an already validated path rather
    # than accepted from a caller.
    temporary = current.with_name(".current.next")
    try:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        temporary.symlink_to(generation)
        os.replace(temporary, current)
    except Exception:
        temporary.unlink(missing_ok=True)
        os.chmod(receipt_path, 0o644)
        receipt_path.unlink(missing_ok=True)
        raise
    return {
        "status": "passed",
        "release": config.release,
        "repository": config.repository_name,
        "generation": generation,
        "previous_generation": previous,
        "current": current_generation(public_root, config),
        "receipt": str(receipt_path),
        "receipt_sha256": kitpro_repo.sha256_file(receipt_path),
    }


def publish_generation(
    source_generation: Path,
    public_root: Path,
    *,
    authorization: PromotionAuthorization | None = None,
    config: ReleaseRepositoryConfig,
    publisher_identity: str = "dry-run-publisher",
    publication_host_identity: str = "dry-run-public-origin",
) -> dict[str, Any]:
    """Compatibility operation with an explicit promotion authorization."""
    if authorization is None:
        raise kitpro_repo.PipelineError("current-pointer promotion requires authorization")
    authorization.validate(config)
    source_validation = validate_generation_tree(source_generation, config)
    if (
        source_validation["generation"] != authorization.generation
        or source_validation["generation_manifest_sha256"] != authorization.manifest_sha256
    ):
        raise kitpro_repo.PipelineError(
            "publication authorization does not match source generation"
        )
    publish_immutable_generation(source_generation, public_root, config=config)
    return promote_current(
        public_root,
        authorization,
        config=config,
        publisher_identity=publisher_identity,
        publication_host_identity=publication_host_identity,
    )


def restore_from_backup(
    backup_root: Path,
    restored_root: Path,
    *,
    config: ReleaseRepositoryConfig,
) -> dict[str, Any]:
    if restored_root.exists() or restored_root.is_symlink():
        raise kitpro_repo.PipelineError("restore destination already exists")
    shutil.copytree(backup_root, restored_root, symlinks=True)
    current = current_generation(restored_root, config)
    if current is None:
        raise kitpro_repo.PipelineError("restored repository has no current pointer")
    receipt = _safe_path(restored_root, "publication-receipts", config.release, f"{current}.json")
    if not receipt.is_file() or receipt.is_symlink():
        raise kitpro_repo.PipelineError(
            "restored repository is missing current publication receipt"
        )
    target = _safe_path(restored_root, "stable", config.release, current)
    validation = validate_generation_tree(target, config)
    receipt_document = kitpro_repo.load_json(receipt)
    if (
        receipt_document.get("release") != config.release
        or receipt_document.get("new_generation") != current
        or kitpro_repo.sha256_file(target / "manifest.json")
        != receipt_document.get("generation_manifest_sha256")
    ):
        raise kitpro_repo.PipelineError("restored current does not match receipt")
    return {
        "status": "passed",
        "release": config.release,
        "repository": config.repository_name,
        "current": current,
        "generation_manifest_sha256": validation["generation_manifest_sha256"],
        "receipt_sha256": kitpro_repo.sha256_file(receipt),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", choices=tuple(RELEASE_CONFIGS), default="1.0")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("client-config")
    validate = subcommands.add_parser("validate-generation")
    validate.add_argument("generation", type=Path)
    validate_rc = subcommands.add_parser("validate-rc-input")
    validate_rc.add_argument("manifest", type=Path)
    validate_rc.add_argument("--output", type=Path)
    immutable = subcommands.add_parser("publish-immutable")
    immutable.add_argument("generation", type=Path)
    immutable.add_argument("public_root", type=Path)
    promote = subcommands.add_parser("promote-current")
    promote.add_argument("public_root", type=Path)
    promote.add_argument("generation")
    promote.add_argument("--manifest-sha256", required=True)
    promote.add_argument("--authorize", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    config = release_config(arguments.release)
    if arguments.command == "client-config":
        print(production_pacman_config(config), end="")
        return 0
    if arguments.command == "validate-generation":
        result = validate_generation_tree(arguments.generation, config)
    elif arguments.command == "validate-rc-input":
        result = validate_rc_input(arguments.manifest, config)
    elif arguments.command == "publish-immutable":
        result = publish_immutable_generation(
            arguments.generation, arguments.public_root, config=config
        )
    elif arguments.command == "promote-current":
        authorization = PromotionAuthorization.create(
            config,
            arguments.generation,
            arguments.manifest_sha256,
            arguments.authorize,
        )
        result = promote_current(arguments.public_root, authorization, config=config)
    else:
        raise AssertionError(arguments.command)
    if getattr(arguments, "output", None):
        kitpro_repo.atomic_write_json(arguments.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
