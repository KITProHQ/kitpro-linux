#!/usr/bin/env python3
"""Build and verify the KITPro Linux Phase 1 repository proof."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GENERATION_RE = re.compile(r"^(?P<release>[0-9]+\.[0-9]+(?:-dev)?)-g(?P<number>[0-9]{4})$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[0-9A-F]{40}$")
PACKAGE_SUFFIXES = (".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz")


class PipelineError(RuntimeError):
    """A controlled pipeline validation or execution failure."""


def run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    input_data: str | bytes | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        env=env,
        input=input_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr if text else completed.stderr.decode(errors="replace")
        stdout = completed.stdout if text else completed.stdout.decode(errors="replace")
        raise PipelineError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    return completed


def require_commands(names: Iterable[str]) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise PipelineError(f"required commands are missing: {', '.join(missing)}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineError(f"cannot read JSON {path}: {error}") from error


def atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write(path, canonical_json_bytes(value))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def snapshot_epoch(snapshot_date: str) -> int:
    try:
        parsed = dt.datetime.strptime(snapshot_date, "%Y/%m/%d").replace(tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise PipelineError("snapshot date must use YYYY/MM/DD") from error
    return int(parsed.timestamp())


def package_release(version: str) -> str:
    if "-" not in version:
        return ""
    return version.rsplit("-", 1)[1]


def parse_key_values(data: bytes) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for raw_line in data.decode(errors="replace").splitlines():
        if " = " not in raw_line:
            continue
        key, value = raw_line.split(" = ", 1)
        result.setdefault(key, []).append(value)
    return result


def package_member(package: Path, member: str) -> bytes:
    completed = run(["bsdtar", "-xOf", str(package), member], text=False)
    return completed.stdout


def package_metadata(package: Path) -> tuple[dict[str, list[str]], dict[str, bytes | None]]:
    pkginfo = package_member(package, ".PKGINFO")
    metadata: dict[str, bytes | None] = {"PKGINFO": pkginfo}
    for archive_name, key in ((".BUILDINFO", "BUILDINFO"), (".MTREE", "MTREE")):
        try:
            metadata[key] = package_member(package, archive_name)
        except PipelineError:
            metadata[key] = None
    return parse_key_values(pkginfo), metadata


def first(metadata: dict[str, list[str]], key: str, default: str = "") -> str:
    values = metadata.get(key, [])
    return values[0] if values else default


def normalize_relation(value: str) -> str:
    return re.split(r"[<>=:]", value, maxsplit=1)[0]


def validate_package_set(document: dict[str, Any]) -> None:
    required = {"schema_version", "release", "architecture", "repository", "explicit_packages", "native_packages"}
    missing = sorted(required - document.keys())
    if missing:
        raise PipelineError(f"package set misses fields: {', '.join(missing)}")
    if document["schema_version"] != 1:
        raise PipelineError("unsupported package-set schema version")
    if not re.fullmatch(r"[0-9]+\.[0-9]+-dev", document["release"]):
        raise PipelineError("Phase 1 release must use a development identifier")
    seen: set[str] = set()
    for package in document["explicit_packages"]:
        for field in ("name", "expected_repository", "support_class", "update_policy", "reason"):
            if not isinstance(package.get(field), str) or not package[field]:
                raise PipelineError(f"explicit package has invalid {field}: {package!r}")
        if package["name"] in seen:
            raise PipelineError(f"duplicate explicit package: {package['name']}")
        seen.add(package["name"])
    for name in document["native_packages"]:
        if not name.startswith("kitpro-linux-"):
            raise PipelineError(f"native package violates namespace: {name}")


def validate_manifest(document: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "release",
        "generation_id",
        "created_at",
        "source_epoch",
        "source_arch_snapshot",
        "channel",
        "repositories",
        "promotion_history",
        "previous_generation",
        "signing",
        "validation",
        "known_exceptions",
    }
    missing = sorted(required - document.keys())
    if missing:
        raise PipelineError(f"manifest misses fields: {', '.join(missing)}")
    if document["schema_version"] != 1:
        raise PipelineError("unsupported generation-manifest schema version")
    if not re.fullmatch(r"[0-9]+\.[0-9]+-dev", document["release"]):
        raise PipelineError("manifest release is not a development release")
    if document["channel"] not in {"edge", "testing", "stable"}:
        raise PipelineError("manifest channel is invalid")
    if document["channel"] == "stable":
        match = GENERATION_RE.fullmatch(document["generation_id"])
        if not match or match.group("release") != document["release"]:
            raise PipelineError("Stable generation ID does not match its release")
    if document["signing"].get("development_only") is not True:
        raise PipelineError("Phase 1 manifest must be development-only")
    if document["validation"].get("status") != "passed":
        raise PipelineError("manifest validation status is not passed")
    repositories = document["repositories"]
    if not isinstance(repositories, list) or not repositories:
        raise PipelineError("manifest must contain a repository")
    filenames: set[str] = set()
    package_names: set[str] = set()
    for repository in repositories:
        if not repository.get("name") or not repository.get("architecture"):
            raise PipelineError("repository identity is incomplete")
        database = repository.get("database", {})
        for field in ("filename", "sha256", "signature_filename", "signature_sha256", "signer_fingerprint"):
            if not database.get(field):
                raise PipelineError(f"repository database misses {field}")
        if not HEX64_RE.fullmatch(database["sha256"]):
            raise PipelineError("repository database hash is invalid")
        if not HEX64_RE.fullmatch(database["signature_sha256"]):
            raise PipelineError("repository database signature hash is invalid")
        if not FINGERPRINT_RE.fullmatch(database["signer_fingerprint"]):
            raise PipelineError("repository database signer fingerprint is invalid")
        for package in repository.get("packages", []):
            package_required = {
                "name",
                "version",
                "package_release",
                "architecture",
                "filename",
                "sha256",
                "origin_type",
                "upstream_origin",
                "upstream_signature",
                "kitpro_signature",
                "source",
                "dependencies",
                "provides",
                "explicit",
                "support_class",
                "update_policy",
                "metadata",
            }
            package_missing = sorted(package_required - package.keys())
            if package_missing:
                raise PipelineError(f"package {package.get('name')} misses {package_missing}")
            if package["name"] in package_names:
                raise PipelineError(f"duplicate package name: {package['name']}")
            package_names.add(package["name"])
            if package["filename"] in filenames:
                raise PipelineError(f"duplicate package filename: {package['filename']}")
            filenames.add(package["filename"])
            if not HEX64_RE.fullmatch(package["sha256"]):
                raise PipelineError(f"invalid package hash: {package['name']}")
            if package["origin_type"] not in {"upstream-binary", "kitpro-rebuild", "kitpro-native"}:
                raise PipelineError(f"invalid origin type: {package['name']}")
            signature = package["kitpro_signature"]
            if not isinstance(signature, dict) or not FINGERPRINT_RE.fullmatch(signature.get("signer_fingerprint", "")):
                raise PipelineError(f"invalid KITPro signature: {package['name']}")
            if package["origin_type"] == "upstream-binary":
                upstream = package["upstream_signature"]
                if not isinstance(upstream, dict) or not FINGERPRINT_RE.fullmatch(upstream.get("signer_fingerprint", "")):
                    raise PipelineError(f"invalid upstream signature: {package['name']}")
    validate_dependency_closure(document)


def validate_dependency_closure(document: dict[str, Any]) -> None:
    packages = [package for repository in document["repositories"] for package in repository["packages"]]
    available = {package["name"] for package in packages}
    for package in packages:
        available.update(normalize_relation(item) for item in package.get("provides", []))
    missing: list[str] = []
    for package in packages:
        for relation in package.get("dependencies", []):
            dependency = normalize_relation(relation)
            if dependency and dependency not in available:
                missing.append(f"{package['name']} -> {relation}")
    if missing:
        raise PipelineError("dependency closure is incomplete:\n" + "\n".join(sorted(missing)))


def ensure_generation_monotonic(release: str, generation: str, stable_root: Path) -> None:
    match = GENERATION_RE.fullmatch(generation)
    if not match or match.group("release") != release:
        raise PipelineError("generation ID must match <release>-gNNNN")
    requested = int(match.group("number"))
    existing: list[int] = []
    if stable_root.exists():
        for child in stable_root.iterdir():
            child_match = GENERATION_RE.fullmatch(child.name)
            if child_match and child_match.group("release") == release:
                existing.append(int(child_match.group("number")))
    if existing and requested <= max(existing) and not (stable_root / generation).exists():
        raise PipelineError("new generation ID must be greater than every existing generation")


def object_path(repo_root: Path, digest: str) -> Path:
    if not HEX64_RE.fullmatch(digest):
        raise PipelineError(f"invalid object digest: {digest}")
    return repo_root / "objects" / "sha256" / digest[:2] / digest


def add_object(repo_root: Path, source: Path) -> str:
    digest = sha256_file(source)
    destination = object_path(repo_root, digest)
    if destination.exists():
        if sha256_file(destination) != digest:
            raise PipelineError(f"content-addressed object is corrupt: {destination}")
        return digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, 0o444)
    try:
        os.link(temporary, destination)
    except FileExistsError:
        pass
    finally:
        temporary.unlink(missing_ok=True)
    if sha256_file(destination) != digest:
        raise PipelineError(f"stored object hash mismatch: {destination}")
    return digest


def materialize_object(repo_root: Path, digest: str, destination: Path) -> None:
    source = object_path(repo_root, digest)
    if not source.is_file() or sha256_file(source) != digest:
        raise PipelineError(f"required object is missing or corrupt: {digest}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    relative = os.path.relpath(source, destination.parent)
    if destination.is_symlink():
        if os.readlink(destination) == relative:
            return
        raise PipelineError(f"existing reference points to a different object: {destination}")
    if destination.exists():
        raise PipelineError(f"refusing to replace existing path: {destination}")
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}")
    os.symlink(relative, temporary)
    os.replace(temporary, destination)


def gpg_fingerprint(home: Path, selector: str) -> str:
    result = run(["gpg", "--homedir", str(home), "--batch", "--with-colons", "--list-keys", selector])
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "fpr":
            fingerprint = fields[9]
            if FINGERPRINT_RE.fullmatch(fingerprint):
                return fingerprint
    raise PipelineError(f"cannot find fingerprint for {selector}")


def gpg_export(home: Path, selectors: Sequence[str]) -> bytes:
    result = run(["gpg", "--homedir", str(home), "--batch", "--export", *selectors], text=False)
    return result.stdout


def gpg_import(home: Path, key_data: bytes) -> None:
    run(["gpg", "--homedir", str(home), "--batch", "--import"], input_data=key_data, text=False)


def create_dev_keys(state_dir: Path, verify_only: bool = False) -> dict[str, Any]:
    require_commands(["gpg"])
    manifest_path = state_dir / "keys.json"
    if manifest_path.exists():
        manifest = load_json(manifest_path)
        verify_dev_keys(state_dir, manifest)
        return manifest
    if verify_only:
        raise PipelineError(f"development key state does not exist: {state_dir}")
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)
    definitions = {
        "root": ("KITPro Linux DEVELOPMENT Root <dev-root@kitpro.invalid>", "cert", "2y", "offline"),
        "package": ("KITPro Linux DEVELOPMENT Package Signing <dev-package@kitpro.invalid>", "sign", "1y", "online"),
        "repository": ("KITPro Linux DEVELOPMENT Repository Signing <dev-repository@kitpro.invalid>", "sign", "1y", "online"),
        "recovery": ("KITPro Linux DEVELOPMENT Recovery <dev-recovery@kitpro.invalid>", "cert", "2y", "offline"),
    }
    roles: dict[str, dict[str, str]] = {}
    for role, (uid, capability, expiration, availability) in definitions.items():
        home = state_dir / role
        home.mkdir(mode=0o700)
        run(
            [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                uid,
                "rsa3072",
                capability,
                expiration,
            ]
        )
        roles[role] = {
            "fingerprint": gpg_fingerprint(home, uid),
            "uid": uid,
            "availability": availability,
            "allowed_use": {
                "root": "certify-delegated-keys",
                "package": "sign-packages",
                "repository": "sign-repository-databases",
                "recovery": "recover-root-trust",
            }[role],
        }
    root_home = state_dir / "root"
    for role in ("package", "repository"):
        public_key = gpg_export(state_dir / role, [roles[role]["fingerprint"]])
        gpg_import(root_home, public_key)
        run(
            [
                "gpg",
                "--homedir",
                str(root_home),
                "--batch",
                "--yes",
                "--passphrase",
                "",
                "--quick-sign-key",
                roles[role]["fingerprint"],
            ]
        )
    gpg_import(root_home, gpg_export(state_dir / "recovery", [roles["recovery"]["fingerprint"]]))
    public_dir = state_dir / "public"
    public_dir.mkdir(mode=0o755)
    all_public = gpg_export(root_home, [entry["fingerprint"] for entry in roles.values()])
    atomic_write(public_dir / "kitpro-linux.gpg", all_public)
    trusted = (
        f"{roles['root']['fingerprint']}:4:\n"
        f"{roles['recovery']['fingerprint']}:4:\n"
    ).encode()
    atomic_write(public_dir / "kitpro-linux-trusted", trusted)
    atomic_write(public_dir / "kitpro-linux-revoked", b"")
    manifest = {
        "schema_version": 1,
        "development_only": True,
        "created_at": utc_now(),
        "roles": roles,
    }
    atomic_write_json(manifest_path, manifest)
    verify_dev_keys(state_dir, manifest)
    return manifest


def verify_dev_keys(state_dir: Path, manifest: dict[str, Any]) -> None:
    if manifest.get("development_only") is not True:
        raise PipelineError("key manifest is not marked development-only")
    for role in ("root", "package", "repository", "recovery"):
        entry = manifest.get("roles", {}).get(role, {})
        if "DEVELOPMENT" not in entry.get("uid", ""):
            raise PipelineError(f"{role} key is not visibly development-only")
        fingerprint = gpg_fingerprint(state_dir / role, entry["fingerprint"])
        if fingerprint != entry["fingerprint"]:
            raise PipelineError(f"{role} fingerprint changed")
    for name in ("kitpro-linux.gpg", "kitpro-linux-trusted", "kitpro-linux-revoked"):
        if not (state_dir / "public" / name).is_file():
            raise PipelineError(f"public keyring component is missing: {name}")


def verify_signature(home: Path, signature: Path, artifact: Path) -> str:
    result = run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--status-fd",
            "1",
            "--verify",
            str(signature),
            str(artifact),
        ]
    )
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            fingerprint = line.split()[2]
            if FINGERPRINT_RE.fullmatch(fingerprint):
                return fingerprint
    raise PipelineError(f"signature has no valid fingerprint: {signature}")


def detached_sign(home: Path, fingerprint: str, artifact: Path, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        existing = verify_signature(home, output, artifact)
        if existing != fingerprint:
            raise PipelineError(f"existing signature uses the wrong key: {output}")
        return
    run(
        [
            "gpg",
            "--homedir",
            str(home),
            "--batch",
            "--yes",
            "--local-user",
            fingerprint,
            "--output",
            str(output),
            "--detach-sign",
            str(artifact),
        ]
    )


def initialize_public_keyring(
    gpg_dir: Path,
    public_keyring: Path,
    trusted_keys: Path,
    revoked_keys: Path,
    *,
    additional_public_keyrings: Sequence[Path] = (),
) -> None:
    marker = gpg_dir / ".kitpro-initialized-v3"
    if marker.exists():
        return
    gpg_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(gpg_dir, 0o700)
    # libalpm's GPGME integration expects pacman's legacy pubring.gpg name.
    # Creating it before import makes GnuPG use that keyring instead of pubring.kbx.
    (gpg_dir / "pubring.kbx").unlink(missing_ok=True)
    (gpg_dir / "pubring.kbx~").unlink(missing_ok=True)
    pubring = gpg_dir / "pubring.gpg"
    pubring.touch(exist_ok=True)
    os.chmod(pubring, 0o644)
    atomic_write(
        gpg_dir / "gpg.conf",
        b"no-greeting\nno-permission-warning\nkeyserver-options import-clean\n",
        0o600,
    )
    run(["gpg", "--homedir", str(gpg_dir), "--batch", "--quiet", "--import",
         str(public_keyring), *(str(path) for path in additional_public_keyrings)])
    if trusted_keys.stat().st_size:
        # pacman-key normally locally signs these distribution roots. This
        # verification-only keyring has no local secret key, so establish the
        # exact listed fingerprints as ultimate trust anchors instead.
        ownertrust: list[str] = []
        for raw_line in trusted_keys.read_text().splitlines():
            fingerprint = raw_line.split(":", 1)[0].strip()
            if FINGERPRINT_RE.fullmatch(fingerprint):
                ownertrust.append(f"{fingerprint}:6:")
        run(
            ["gpg", "--homedir", str(gpg_dir), "--batch", "--import-ownertrust"],
            input_data="\n".join(ownertrust) + "\n",
        )
    if revoked_keys.stat().st_size:
        for raw_line in revoked_keys.read_text().splitlines():
            fingerprint = raw_line.strip()
            if not fingerprint or fingerprint.startswith("#"):
                continue
            listed = subprocess.run(
                ["gpg", "--homedir", str(gpg_dir), "--batch", "--list-keys", fingerprint],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if listed.returncode == 0:
                run(
                    [
                        "gpg",
                        "--homedir",
                        str(gpg_dir),
                        "--command-fd",
                        "0",
                        "--no-auto-check-trustdb",
                        "--quiet",
                        "--batch",
                        "--edit-key",
                        fingerprint,
                    ],
                    input_data="disable\nquit\n",
                )
    run(["gpg", "--homedir", str(gpg_dir), "--batch", "--check-trustdb"])
    atomic_write(marker, b"public keyring initialized by KITPro Linux tooling\n", 0o600)


def setup_arch_keyring(gpg_dir: Path) -> None:
    keyring_root = Path("/usr/share/pacman/keyrings")
    initialize_public_keyring(
        gpg_dir,
        keyring_root / "archlinux.gpg",
        keyring_root / "archlinux-trusted",
        keyring_root / "archlinux-revoked",
    )


def setup_kitpro_keyring(gpg_dir: Path, public_dir: Path) -> None:
    initialize_public_keyring(
        gpg_dir,
        public_dir / "kitpro-linux.gpg",
        public_dir / "kitpro-linux-trusted",
        public_dir / "kitpro-linux-revoked",
    )


def render_template(source: Path, destination: Path, replacements: dict[str, str]) -> None:
    content = source.read_text()
    for key, value in replacements.items():
        content = content.replace(f"@{key}@", value)
    remaining = sorted(set(re.findall(r"@[A-Z0-9_]+@", content)))
    if remaining:
        raise PipelineError(f"unresolved template values in {source}: {remaining}")
    atomic_write(destination, content.encode())


def download(url: str, destination: Path) -> None:
    if destination.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        os.replace(temporary, destination)
    except Exception as error:
        temporary.unlink(missing_ok=True)
        raise PipelineError(f"download failed: {url}: {error}") from error


def ingest_snapshot(
    snapshot_date_value: str,
    package_set_path: Path,
    repo_root: Path,
    state_root: Path,
    lock_output: Path | None = None,
) -> Path:
    require_commands(["pacman", "fakeroot", "gpg", "bsdtar"])
    package_set = load_json(package_set_path)
    validate_package_set(package_set)
    epoch = snapshot_epoch(snapshot_date_value)
    ingest_state = state_root / "ingest" / snapshot_date_value.replace("/", "-")
    db_path = ingest_state / "db"
    cache_path = ingest_state / "cache"
    arch_gpg_path = ingest_state / "arch-gnupg"
    log_path = ingest_state / "pacman.log"
    for directory in (db_path / "sync", cache_path):
        directory.mkdir(parents=True, exist_ok=True)
    setup_arch_keyring(arch_gpg_path)
    config_path = ingest_state / "pacman.conf"
    render_template(
        PROJECT_ROOT / "config" / "arch-pacman.conf.in",
        config_path,
        {
            "DB_PATH": str(db_path.resolve()),
            "CACHE_PATH": str(cache_path.resolve()),
            "ARCH_GPG_PATH": str(arch_gpg_path.resolve()),
            "LOG_PATH": str(log_path.resolve()),
            "SNAPSHOT_DATE": snapshot_date_value,
        },
    )
    run(["fakeroot", "pacman", "-Sy", "--noconfirm", "--config", str(config_path)])
    database_hashes: dict[str, str] = {}
    for database in sorted((db_path / "sync").glob("*.db")):
        database_hashes[database.name] = sha256_file(database)
    if not database_hashes:
        raise PipelineError("pacman synchronized no repository databases")
    combined = hashlib.sha256(canonical_json_bytes(database_hashes)).hexdigest()
    compact_date = snapshot_date_value.replace("/", "-")
    snapshot_id = f"arch-{compact_date}T000000Z-{combined[:12]}"
    snapshot_root = repo_root / "ingest" / snapshot_id
    manifest_path = snapshot_root / "snapshot-manifest.json"
    if manifest_path.exists():
        manifest = load_json(manifest_path)
        verify_snapshot_manifest(manifest, repo_root)
        if manifest["source_arch_snapshot"]["database_hashes"] != database_hashes:
            raise PipelineError("existing snapshot uses different repository databases")
        return snapshot_root
    explicit_names = [entry["name"] for entry in package_set["explicit_packages"]]
    print_result = run(
        [
            "pacman",
            "-Sp",
            "--config",
            str(config_path),
            "--print-format",
            "%r|%n|%v|%l",
            *explicit_names,
        ]
    )
    resolved: dict[str, dict[str, str]] = {}
    for line in print_result.stdout.splitlines():
        parts = line.strip().split("|", 3)
        if len(parts) != 4:
            continue
        repository, name, version, url = parts
        if url.startswith("file://"):
            cached_filename = urllib.parse.unquote(Path(urllib.parse.urlparse(url).path).name)
            url = (
                f"https://archive.archlinux.org/repos/{snapshot_date_value}/"
                f"{repository}/os/{package_set['architecture']}/"
                f"{urllib.parse.quote(cached_filename)}"
            )
        if not url.startswith(("http://", "https://")):
            continue
        resolved[name] = {"repository": repository, "name": name, "version": version, "url": url}
    if not resolved:
        raise PipelineError("pacman resolved no packages")
    run(
        ["fakeroot", "pacman", "-Sw", "--noconfirm", "--config", str(config_path), *explicit_names]
    )
    explicit_policy = {entry["name"]: entry for entry in package_set["explicit_packages"]}
    package_records: list[dict[str, Any]] = []
    exceptions: list[dict[str, str]] = []
    metadata_root = snapshot_root / "metadata"
    packages_root = snapshot_root / "packages"
    packages_root.mkdir(parents=True, exist_ok=True)
    for name, resolved_entry in sorted(resolved.items()):
        filename = urllib.parse.unquote(Path(urllib.parse.urlparse(resolved_entry["url"]).path).name)
        package_file = cache_path / filename
        if not package_file.is_file():
            raise PipelineError(f"downloaded package is missing: {filename}")
        signature_file = cache_path / f"{filename}.arch.sig"
        download(f"{resolved_entry['url']}.sig", signature_file)
        upstream_fingerprint = verify_signature(arch_gpg_path, signature_file, package_file)
        package_hash = add_object(repo_root, package_file)
        signature_hash = add_object(repo_root, signature_file)
        materialize_object(repo_root, package_hash, packages_root / filename)
        materialize_object(repo_root, signature_hash, packages_root / f"{filename}.arch.sig")
        pkginfo, metadata_files = package_metadata(package_file)
        metadata_hashes: dict[str, str | None] = {}
        package_metadata_root = metadata_root / filename
        package_metadata_root.mkdir(parents=True, exist_ok=True)
        for metadata_name, data in metadata_files.items():
            if data is None:
                metadata_hashes[metadata_name.lower()] = None
                exceptions.append({"type": "missing-package-metadata", "package": name, "field": metadata_name})
                continue
            metadata_path = package_metadata_root / metadata_name
            atomic_write(metadata_path, data)
            metadata_hashes[metadata_name.lower()] = sha256_bytes(data)
        policy = explicit_policy.get(name)
        repository = resolved_entry["repository"]
        if policy and repository != policy["expected_repository"]:
            raise PipelineError(
                f"explicit package {name} resolved from {repository}, expected {policy['expected_repository']}"
            )
        pkgbase = first(pkginfo, "pkgbase", name)
        package_record = {
            "name": first(pkginfo, "pkgname", name),
            "version": first(pkginfo, "pkgver", resolved_entry["version"]),
            "package_release": package_release(first(pkginfo, "pkgver", resolved_entry["version"])),
            "architecture": first(pkginfo, "arch", package_set["architecture"]),
            "filename": filename,
            "sha256": package_hash,
            "object_sha256": package_hash,
            "origin_type": "upstream-binary",
            "upstream_origin": {
                "repository": repository,
                "package_url": resolved_entry["url"],
                "project_url": first(pkginfo, "url"),
            },
            "upstream_signature": {
                "filename": f"{filename}.arch.sig",
                "sha256": signature_hash,
                "object_sha256": signature_hash,
                "signer_fingerprint": upstream_fingerprint,
            },
            "kitpro_signature": None,
            "source": {
                "packaging_git_url": f"https://gitlab.archlinux.org/archlinux/packaging/packages/{pkgbase}.git",
                "packaging_commit": None,
            },
            "dependencies": pkginfo.get("depend", []),
            "provides": pkginfo.get("provides", []),
            "explicit": policy is not None,
            "support_class": policy["support_class"] if policy else "dependency",
            "update_policy": policy["update_policy"] if policy else "follows-dependent-update-set",
            "metadata": metadata_hashes,
        }
        package_records.append(package_record)
    exceptions.append(
        {
            "type": "packaging-commit-unresolved",
            "reason": "pkgctl is not installed; packaging Git URLs are recorded without commit IDs",
        }
    )
    snapshot_root.mkdir(parents=True, exist_ok=True)
    database_archive_root = snapshot_root / "repository-databases"
    database_archive_root.mkdir(parents=True, exist_ok=True)
    for database in sorted((db_path / "sync").glob("*.db")):
        shutil.copyfile(database, database_archive_root / database.name)
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "source_epoch": epoch,
        "source_arch_snapshot": {
            "id": snapshot_id,
            "archive_date": snapshot_date_value,
            "database_hashes": database_hashes,
        },
        "package_set": package_set,
        "packages": package_records,
        "known_exceptions": exceptions,
        "validation": {
            "status": "passed",
            "checks": [
                "arch-keyring-signatures",
                "package-hashes",
                "pacman-dependency-resolution",
                "explicit-repository-origin",
                "package-metadata-capture",
            ],
        },
    }
    atomic_write_json(manifest_path, manifest)
    verify_snapshot_manifest(manifest, repo_root)
    if lock_output is not None:
        explicit_records = [entry for entry in package_records if entry["explicit"]]
        lock = {
            "schema_version": 1,
            "release": package_set["release"],
            "snapshot": manifest["source_arch_snapshot"],
            "explicit_packages": explicit_records,
        }
        atomic_write_json(lock_output, lock)
    return snapshot_root


def verify_snapshot_manifest(manifest: dict[str, Any], repo_root: Path) -> None:
    if manifest.get("validation", {}).get("status") != "passed":
        raise PipelineError("snapshot validation did not pass")
    names: set[str] = set()
    for package in manifest.get("packages", []):
        if package["name"] in names:
            raise PipelineError(f"duplicate snapshot package: {package['name']}")
        names.add(package["name"])
        package_object = object_path(repo_root, package["sha256"])
        if not package_object.is_file() or sha256_file(package_object) != package["sha256"]:
            raise PipelineError(f"snapshot package object is missing: {package['name']}")
        signature = package["upstream_signature"]
        signature_object = object_path(repo_root, signature["sha256"])
        if not signature_object.is_file() or sha256_file(signature_object) != signature["sha256"]:
            raise PipelineError(f"snapshot signature object is missing: {package['name']}")


def build_native_packages(
    snapshot_root: Path,
    package_set_path: Path,
    repo_root: Path,
    state_root: Path,
    key_state: Path,
) -> Path:
    require_commands(["makepkg", "bsdtar", "gpg"])
    output_manifest = state_root / "native" / "manifest.json"
    if output_manifest.exists():
        manifest = load_json(output_manifest)
        for package in manifest["packages"]:
            path = object_path(repo_root, package["sha256"])
            if not path.is_file() or sha256_file(path) != package["sha256"]:
                raise PipelineError(f"native object is missing: {package['name']}")
        return output_manifest
    snapshot = load_json(snapshot_root / "snapshot-manifest.json")
    package_set = load_json(package_set_path)
    keys = create_dev_keys(key_state)
    package_fingerprint = keys["roles"]["package"]["fingerprint"]
    build_root = state_root / "native-build"
    destination = state_root / "native" / "packages"
    destination.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    source_commit = run(["git", "-C", str(PROJECT_ROOT), "rev-parse", "HEAD"]).stdout.strip()
    policies = {
        "kitpro-linux-release": ("core", "release-bound"),
        "kitpro-linux-keyring": ("security-sensitive", "trust-lifecycle"),
        "kitpro-linux-base": ("core", "release-bound"),
    }
    for name in package_set["native_packages"]:
        source_dir = PROJECT_ROOT / "packages" / name
        work_dir = build_root / name
        if work_dir.exists():
            shutil.rmtree(work_dir)
        shutil.copytree(source_dir, work_dir)
        if name == "kitpro-linux-keyring":
            public_dir = key_state / "public"
            for public_name in ("kitpro-linux.gpg", "kitpro-linux-trusted", "kitpro-linux-revoked"):
                shutil.copyfile(public_dir / public_name, work_dir / public_name)
            template = (work_dir / "PKGBUILD.in").read_text()
            replacements = {
                "@GPG_SHA256@": sha256_file(work_dir / "kitpro-linux.gpg"),
                "@TRUSTED_SHA256@": sha256_file(work_dir / "kitpro-linux-trusted"),
                "@REVOKED_SHA256@": sha256_file(work_dir / "kitpro-linux-revoked"),
            }
            for old, new in replacements.items():
                template = template.replace(old, new)
            atomic_write(work_dir / "PKGBUILD", template.encode())
        environment = os.environ.copy()
        environment.update(
            {
                "GNUPGHOME": str((key_state / "package").resolve()),
                "PKGDEST": str(destination.resolve()),
                "SOURCE_DATE_EPOCH": str(snapshot["source_epoch"]),
                "PACKAGER": "KITPro Linux DEVELOPMENT Package Builder <dev-package@kitpro.invalid>",
            }
        )
        run(
            [
                "makepkg",
                "--nodeps",
                "--cleanbuild",
                "--force",
                "--sign",
                "--key",
                package_fingerprint,
            ],
            cwd=work_dir,
            env=environment,
        )
        candidates = sorted(destination.glob(f"{name}-*.pkg.tar.*"))
        candidates = [candidate for candidate in candidates if not candidate.name.endswith(".sig")]
        if len(candidates) != 1:
            raise PipelineError(f"expected one built artifact for {name}, found {len(candidates)}")
        package_file = candidates[0]
        signature_file = package_file.with_name(f"{package_file.name}.sig")
        signer = verify_signature(key_state / "package", signature_file, package_file)
        package_hash = add_object(repo_root, package_file)
        signature_hash = add_object(repo_root, signature_file)
        pkginfo, metadata_files = package_metadata(package_file)
        metadata_hashes = {
            key.lower(): sha256_bytes(data) if data is not None else None
            for key, data in metadata_files.items()
        }
        support_class, update_policy = policies[name]
        records.append(
            {
                "name": first(pkginfo, "pkgname", name),
                "version": first(pkginfo, "pkgver"),
                "package_release": package_release(first(pkginfo, "pkgver")),
                "architecture": first(pkginfo, "arch", "any"),
                "filename": package_file.name,
                "sha256": package_hash,
                "object_sha256": package_hash,
                "origin_type": "kitpro-native",
                "upstream_origin": None,
                "upstream_signature": None,
                "kitpro_signature": {
                    "filename": signature_file.name,
                    "sha256": signature_hash,
                    "object_sha256": signature_hash,
                    "signer_fingerprint": signer,
                },
                "source": {
                    "repository": "KITProHQ/kitpro-linux",
                    "path": str(source_dir.relative_to(PROJECT_ROOT)),
                    "packaging_commit": source_commit,
                },
                "dependencies": pkginfo.get("depend", []),
                "provides": pkginfo.get("provides", []),
                "explicit": True,
                "support_class": support_class,
                "update_policy": update_policy,
                "metadata": metadata_hashes,
            }
        )
    manifest = {
        "schema_version": 1,
        "created_at": utc_now(),
        "development_only": True,
        "source_arch_snapshot": snapshot["source_arch_snapshot"],
        "packages": records,
    }
    atomic_write_json(output_manifest, manifest)
    return output_manifest


def artifact_set_hash(packages: Sequence[dict[str, Any]]) -> str:
    payload = [{"filename": package["filename"], "sha256": package["sha256"]} for package in packages]
    return hashlib.sha256(canonical_json_bytes(sorted(payload, key=lambda item: item["filename"]))).hexdigest()


def normalize_tar_gz(path: Path, source_epoch_value: int) -> None:
    with tempfile.TemporaryDirectory(prefix="kitpro-repo-db-") as temporary_name:
        temporary = Path(temporary_name)
        extract_root = temporary / "extract"
        extract_root.mkdir()
        run(["bsdtar", "-xf", str(path), "-C", str(extract_root)])
        entries = sorted(item.name for item in extract_root.iterdir())
        if not entries:
            raise PipelineError(f"repository database is empty: {path}")
        tar_command = [
            "tar",
            "--sort=name",
            f"--mtime=@{source_epoch_value}",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "--format=ustar",
            "-C",
            str(extract_root),
            "-cf",
            "-",
            *entries,
        ]
        tar_process = subprocess.Popen(tar_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert tar_process.stdout is not None
        gzip_process = subprocess.Popen(
            ["gzip", "-n", "-9"],
            stdin=tar_process.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        tar_process.stdout.close()
        compressed, gzip_error = gzip_process.communicate()
        _, tar_error = tar_process.communicate()
        if tar_process.returncode != 0 or gzip_process.returncode != 0:
            raise PipelineError(
                "deterministic repository compression failed:\n"
                f"tar: {tar_error.decode(errors='replace')}\n"
                f"gzip: {gzip_error.decode(errors='replace')}"
            )
        atomic_write(path, compressed)


def build_repository_database(
    repository_dir: Path,
    repository_name: str,
    package_files: Sequence[Path],
    source_epoch_value: int,
    key_state: Path,
) -> tuple[Path, Path, Path]:
    require_commands(["repo-add", "bsdtar", "tar", "gzip", "gpg"])
    database = repository_dir / f"{repository_name}.db.tar.gz"
    files_database = repository_dir / f"{repository_name}.files.tar.gz"
    for stale in (
        database,
        files_database,
        repository_dir / f"{repository_name}.db",
        repository_dir / f"{repository_name}.files",
    ):
        stale.unlink(missing_ok=True)
    run(["repo-add", "--include-sigs", str(database), *[str(path) for path in package_files]])
    normalize_tar_gz(database, source_epoch_value)
    normalize_tar_gz(files_database, source_epoch_value)
    database_link = repository_dir / f"{repository_name}.db"
    files_link = repository_dir / f"{repository_name}.files"
    database_link.unlink(missing_ok=True)
    files_link.unlink(missing_ok=True)
    os.symlink(database.name, database_link)
    os.symlink(files_database.name, files_link)
    key_manifest = load_json(key_state / "keys.json")
    repository_fingerprint = key_manifest["roles"]["repository"]["fingerprint"]
    signature = database.with_name(f"{database.name}.sig")
    detached_sign(key_state / "repository", repository_fingerprint, database, signature)
    return database, signature, files_database


def store_and_reference_file(repo_root: Path, source: Path, destination: Path) -> str:
    digest = add_object(repo_root, source)
    source.unlink()
    materialize_object(repo_root, digest, destination)
    return digest


def materialize_manifest_repository(repo_root: Path, root: Path, manifest: dict[str, Any]) -> None:
    for repository in manifest["repositories"]:
        repository_dir = root / "core" / "os" / repository["architecture"]
        for package in repository["packages"]:
            materialize_object(repo_root, package["object_sha256"], repository_dir / package["filename"])
            signature = package["kitpro_signature"]
            materialize_object(repo_root, signature["object_sha256"], repository_dir / signature["filename"])
        database = repository["database"]
        materialize_object(repo_root, database["object_sha256"], repository_dir / database["filename"])
        materialize_object(
            repo_root,
            database["signature_object_sha256"],
            repository_dir / database["signature_filename"],
        )
        materialize_object(
            repo_root,
            database["files_object_sha256"],
            repository_dir / database["files_filename"],
        )
        for short_name, target in (
            (f"{repository['name']}.db", database["filename"]),
            (f"{repository['name']}.db.sig", database["signature_filename"]),
            (f"{repository['name']}.files", database["files_filename"]),
        ):
            link = repository_dir / short_name
            if link.is_symlink():
                if os.readlink(link) != target:
                    raise PipelineError(f"repository alias points to the wrong file: {link}")
            elif link.exists():
                raise PipelineError(f"repository alias path is not a symlink: {link}")
            else:
                os.symlink(target, link)


def create_edge(
    snapshot_root: Path,
    release: str,
    repo_root: Path,
    state_root: Path,
    key_state: Path,
    package_set_path: Path,
) -> Path:
    edge_root = repo_root / "edge"
    manifest_path = edge_root / "manifest.json"
    if manifest_path.exists():
        manifest = load_json(manifest_path)
        validate_manifest(manifest)
        verify_manifest_artifacts(manifest, repo_root, edge_root, key_state)
        return manifest_path
    snapshot = load_json(snapshot_root / "snapshot-manifest.json")
    if snapshot["package_set"]["release"] != release:
        raise PipelineError("snapshot belongs to a different release")
    native_manifest_path = build_native_packages(
        snapshot_root,
        package_set_path,
        repo_root,
        state_root,
        key_state,
    )
    native = load_json(native_manifest_path)
    keys = create_dev_keys(key_state)
    package_fingerprint = keys["roles"]["package"]["fingerprint"]
    signature_work = state_root / "kitpro-signatures"
    packages: list[dict[str, Any]] = []
    for source_record in snapshot["packages"]:
        record = json.loads(json.dumps(source_record))
        package_object = object_path(repo_root, record["object_sha256"])
        signature_path = signature_work / f"{record['filename']}.sig"
        detached_sign(key_state / "package", package_fingerprint, package_object, signature_path)
        signature_hash = add_object(repo_root, signature_path)
        record["kitpro_signature"] = {
            "filename": f"{record['filename']}.sig",
            "sha256": signature_hash,
            "object_sha256": signature_hash,
            "signer_fingerprint": package_fingerprint,
        }
        packages.append(record)
    packages.extend(native["packages"])
    packages.sort(key=lambda item: item["name"])
    repository_name = f"kitpro-{release}-core"
    repository_dir = edge_root / "core" / "os" / "x86_64"
    repository_dir.mkdir(parents=True, exist_ok=False)
    for package in packages:
        materialize_object(repo_root, package["object_sha256"], repository_dir / package["filename"])
        signature = package["kitpro_signature"]
        materialize_object(repo_root, signature["object_sha256"], repository_dir / signature["filename"])
    package_files = [repository_dir / package["filename"] for package in packages]
    database, database_signature, files_database = build_repository_database(
        repository_dir,
        repository_name,
        package_files,
        snapshot["source_epoch"],
        key_state,
    )
    database_hash = store_and_reference_file(repo_root, database, repository_dir / database.name)
    database_signature_hash = store_and_reference_file(
        repo_root,
        database_signature,
        repository_dir / database_signature.name,
    )
    files_hash = store_and_reference_file(repo_root, files_database, repository_dir / files_database.name)
    artifact_hash = artifact_set_hash(packages)
    manifest = {
        "schema_version": 1,
        "release": release,
        "generation_id": f"edge-{artifact_hash[:12]}",
        "created_at": utc_now(),
        "source_epoch": snapshot["source_epoch"],
        "source_arch_snapshot": snapshot["source_arch_snapshot"],
        "channel": "edge",
        "repositories": [
            {
                "name": repository_name,
                "architecture": "x86_64",
                "database": {
                    "filename": database.name,
                    "sha256": database_hash,
                    "object_sha256": database_hash,
                    "signature_filename": database_signature.name,
                    "signature_sha256": database_signature_hash,
                    "signature_object_sha256": database_signature_hash,
                    "signer_fingerprint": keys["roles"]["repository"]["fingerprint"],
                    "files_filename": files_database.name,
                    "files_sha256": files_hash,
                    "files_object_sha256": files_hash,
                },
                "packages": packages,
            }
        ],
        "promotion_history": [
            {
                "from": "ingest",
                "to": "edge",
                "at": utc_now(),
                "artifact_set_sha256": artifact_hash,
            }
        ],
        "previous_generation": None,
        "signing": {"development_only": True, "roles": keys["roles"]},
        "validation": {
            "status": "passed",
            "checks": [
                "manifest-schema",
                "package-hashes",
                "upstream-signatures",
                "kitpro-package-signatures",
                "dependency-closure",
                "repository-database-signature",
            ],
        },
        "known_exceptions": snapshot["known_exceptions"],
    }
    validate_manifest(manifest)
    materialize_manifest_repository(repo_root, edge_root, manifest)
    atomic_write_json(manifest_path, manifest)
    verify_manifest_artifacts(manifest, repo_root, edge_root, key_state)
    return manifest_path


def promote(release: str, repo_root: Path, key_state: Path, source: str, target: str) -> Path:
    allowed = {("edge", "testing")}
    if (source, target) not in allowed:
        raise PipelineError(f"unsupported promotion: {source} -> {target}")
    source_root = repo_root / source
    target_root = repo_root / target
    source_manifest = load_json(source_root / "manifest.json")
    validate_manifest(source_manifest)
    if source_manifest["release"] != release:
        raise PipelineError("cross-release promotion is forbidden")
    target_manifest_path = target_root / "manifest.json"
    if target_manifest_path.exists():
        existing = load_json(target_manifest_path)
        validate_manifest(existing)
        if manifest_artifact_hash(existing) != manifest_artifact_hash(source_manifest):
            raise PipelineError("existing target contains a different artifact set")
        verify_manifest_artifacts(existing, repo_root, target_root, key_state)
        return target_manifest_path
    target_manifest = json.loads(json.dumps(source_manifest))
    target_manifest["channel"] = target
    target_manifest["generation_id"] = f"{target}-{manifest_artifact_hash(source_manifest)[:12]}"
    target_manifest["created_at"] = utc_now()
    target_manifest["promotion_history"].append(
        {
            "from": source,
            "to": target,
            "at": utc_now(),
            "artifact_set_sha256": manifest_artifact_hash(source_manifest),
        }
    )
    materialize_manifest_repository(repo_root, target_root, target_manifest)
    atomic_write_json(target_manifest_path, target_manifest)
    validate_manifest(target_manifest)
    verify_manifest_artifacts(target_manifest, repo_root, target_root, key_state)
    return target_manifest_path


def manifest_artifact_hash(manifest: dict[str, Any]) -> str:
    return artifact_set_hash(
        [package for repository in manifest["repositories"] for package in repository["packages"]]
    )


def publish(
    release: str,
    generation: str,
    repo_root: Path,
    key_state: Path,
) -> Path:
    source_root = repo_root / "testing"
    source_manifest = load_json(source_root / "manifest.json")
    validate_manifest(source_manifest)
    if source_manifest["release"] != release:
        raise PipelineError("cross-release publication is forbidden")
    stable_release_root = repo_root / "stable" / release
    ensure_generation_monotonic(release, generation, stable_release_root)
    generation_root = stable_release_root / generation
    manifest_path = generation_root / "manifest.json"
    if manifest_path.exists():
        existing = load_json(manifest_path)
        validate_manifest(existing)
        if manifest_artifact_hash(existing) != manifest_artifact_hash(source_manifest):
            raise PipelineError("existing Stable generation has different artifacts")
        verify_manifest_artifacts(existing, repo_root, generation_root, key_state)
        set_current(stable_release_root, generation)
        return manifest_path
    previous: str | None = None
    current = stable_release_root / "current"
    if current.is_symlink():
        previous = Path(os.readlink(current)).name
    stable_manifest = json.loads(json.dumps(source_manifest))
    stable_manifest["channel"] = "stable"
    stable_manifest["generation_id"] = generation
    stable_manifest["created_at"] = utc_now()
    stable_manifest["previous_generation"] = previous
    stable_manifest["promotion_history"].append(
        {
            "from": "testing",
            "to": "stable",
            "at": utc_now(),
            "artifact_set_sha256": manifest_artifact_hash(source_manifest),
        }
    )
    materialize_manifest_repository(repo_root, generation_root, stable_manifest)
    atomic_write_json(manifest_path, stable_manifest)
    validate_manifest(stable_manifest)
    verify_manifest_artifacts(stable_manifest, repo_root, generation_root, key_state)
    archive_root = repo_root / "archive" / release / generation
    archive_root.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(manifest_path, archive_root / "manifest.json")
    referenced_objects = sorted(manifest_object_hashes(stable_manifest))
    atomic_write_json(archive_root / "objects.json", {"sha256": referenced_objects})
    for path in sorted(generation_root.rglob("*"), reverse=True):
        if not path.is_symlink():
            os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(generation_root, 0o555)
    for path in sorted(archive_root.rglob("*"), reverse=True):
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(archive_root, 0o555)
    set_current(stable_release_root, generation)
    return manifest_path


def set_current(stable_release_root: Path, generation: str) -> None:
    target = stable_release_root / generation
    if not target.is_dir():
        raise PipelineError(f"current target does not exist: {target}")
    current = stable_release_root / "current"
    if current.is_symlink() and os.readlink(current) == generation:
        return
    temporary = stable_release_root / f".current.{os.getpid()}"
    temporary.unlink(missing_ok=True)
    os.symlink(generation, temporary)
    os.replace(temporary, current)


def manifest_object_hashes(manifest: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for repository in manifest["repositories"]:
        database = repository["database"]
        hashes.update(
            {
                database["object_sha256"],
                database["signature_object_sha256"],
                database["files_object_sha256"],
            }
        )
        for package in repository["packages"]:
            hashes.add(package["object_sha256"])
            hashes.add(package["kitpro_signature"]["object_sha256"])
            if package["upstream_signature"]:
                hashes.add(package["upstream_signature"]["object_sha256"])
    return hashes


def verify_manifest_artifacts(
    manifest: dict[str, Any],
    repo_root: Path,
    channel_root: Path,
    key_state: Path,
) -> None:
    validate_manifest(manifest)
    keys = load_json(key_state / "keys.json")
    for digest in manifest_object_hashes(manifest):
        path = object_path(repo_root, digest)
        if not path.is_file() or sha256_file(path) != digest:
            raise PipelineError(f"manifest object is missing or corrupt: {digest}")
    for repository in manifest["repositories"]:
        repository_dir = channel_root / "core" / "os" / repository["architecture"]
        for package in repository["packages"]:
            package_path = repository_dir / package["filename"]
            signature_path = repository_dir / package["kitpro_signature"]["filename"]
            if sha256_file(package_path) != package["sha256"]:
                raise PipelineError(f"channel package hash changed: {package['name']}")
            signer = verify_signature(key_state / "package", signature_path, package_path)
            if signer != keys["roles"]["package"]["fingerprint"]:
                raise PipelineError(f"wrong package signer: {package['name']}")
        database = repository["database"]
        database_path = repository_dir / database["filename"]
        database_signature = repository_dir / database["signature_filename"]
        if sha256_file(database_path) != database["sha256"]:
            raise PipelineError("repository database hash changed")
        signer = verify_signature(key_state / "repository", database_signature, database_path)
        if signer != database["signer_fingerprint"]:
            raise PipelineError("repository database signer changed")


def reconstruct(
    release: str,
    generation: str,
    repo_root: Path,
    key_state: Path,
    output: Path,
) -> dict[str, Any]:
    archive_root = repo_root / "archive" / release / generation
    manifest = load_json(archive_root / "manifest.json")
    validate_manifest(manifest)
    if manifest["release"] != release or manifest["generation_id"] != generation:
        raise PipelineError("archive identity does not match reconstruction request")
    objects_index = load_json(archive_root / "objects.json")["sha256"]
    expected_objects = sorted(manifest_object_hashes(manifest))
    if objects_index != expected_objects:
        raise PipelineError("archive object index does not match its manifest")
    if output.exists():
        shutil.rmtree(output)
    repository = manifest["repositories"][0]
    repository_dir = output / "core" / "os" / repository["architecture"]
    repository_dir.mkdir(parents=True)
    for package in repository["packages"]:
        shutil.copyfile(object_path(repo_root, package["object_sha256"]), repository_dir / package["filename"])
        signature = package["kitpro_signature"]
        shutil.copyfile(
            object_path(repo_root, signature["object_sha256"]),
            repository_dir / signature["filename"],
        )
    package_files = [repository_dir / package["filename"] for package in repository["packages"]]
    database, database_signature, files_database = build_repository_database(
        repository_dir,
        repository["name"],
        package_files,
        manifest["source_epoch"],
        key_state,
    )
    # Database signatures contain a creation time. Reconstruction compares the
    # deterministic database bytes and verifies the published signature instead.
    database_signature.unlink(missing_ok=True)
    published_signature = object_path(repo_root, repository["database"]["signature_object_sha256"])
    shutil.copyfile(published_signature, repository_dir / repository["database"]["signature_filename"])
    package_mismatches = [
        package["filename"]
        for package in repository["packages"]
        if sha256_file(repository_dir / package["filename"]) != package["sha256"]
    ]
    database_hash = sha256_file(database)
    files_hash = sha256_file(files_database)
    database_match = database_hash == repository["database"]["sha256"]
    files_match = files_hash == repository["database"]["files_sha256"]
    signer = verify_signature(
        key_state / "repository",
        repository_dir / repository["database"]["signature_filename"],
        database,
    )
    report = {
        "schema_version": 1,
        "release": release,
        "generation": generation,
        "package_count": len(repository["packages"]),
        "package_hash_mismatches": package_mismatches,
        "repository_database": {
            "expected_sha256": repository["database"]["sha256"],
            "actual_sha256": database_hash,
            "identical": database_match,
            "signature_valid": signer == repository["database"]["signer_fingerprint"],
        },
        "files_database": {
            "expected_sha256": repository["database"]["files_sha256"],
            "actual_sha256": files_hash,
            "identical": files_match,
        },
        "manifest_inventory_identical": True,
        "result": "passed" if not package_mismatches and database_match and files_match else "failed",
    }
    atomic_write_json(output / "reconstruction-report.json", report)
    if report["result"] != "passed":
        raise PipelineError(f"reconstruction differs: {json.dumps(report, indent=2)}")
    return report


def render_client_config(
    repo_root: Path,
    release: str,
    state_root: Path,
    key_state: Path,
) -> Path:
    client_state = state_root / "client"
    db_path = client_state / "db"
    cache_path = client_state / "cache"
    gpg_path = client_state / "gnupg"
    log_path = client_state / "pacman.log"
    for directory in (db_path / "sync", cache_path):
        directory.mkdir(parents=True, exist_ok=True)
    setup_kitpro_keyring(gpg_path, key_state / "public")
    config_path = client_state / "pacman.conf"
    render_template(
        PROJECT_ROOT / "config" / "kitpro-client.conf.in",
        config_path,
        {
            "DB_PATH": str(db_path.resolve()),
            "CACHE_PATH": str(cache_path.resolve()),
            "KITPRO_GPG_PATH": str(gpg_path.resolve()),
            "LOG_PATH": str(log_path.resolve()),
            "STABLE_CURRENT": str((repo_root / "stable" / release / "current").resolve()),
        },
    )
    return config_path


def verify_phase1(repo_root: Path, state_root: Path, release: str, generation: str) -> dict[str, Any]:
    key_state = state_root / "dev-keys"
    keys = create_dev_keys(key_state, verify_only=True)
    stable_root = repo_root / "stable" / release / generation
    manifest = load_json(stable_root / "manifest.json")
    validate_manifest(manifest)
    verify_manifest_artifacts(manifest, repo_root, stable_root, key_state)
    edge = load_json(repo_root / "edge" / "manifest.json")
    testing = load_json(repo_root / "testing" / "manifest.json")
    hashes = {
        "edge": manifest_artifact_hash(edge),
        "testing": manifest_artifact_hash(testing),
        "stable": manifest_artifact_hash(manifest),
    }
    if len(set(hashes.values())) != 1:
        raise PipelineError(f"promotion changed artifact hashes: {hashes}")
    config_path = render_client_config(repo_root, release, state_root, key_state)
    run(["fakeroot", "pacman", "-Sy", "--noconfirm", "--config", str(config_path)])
    resolution = run(
        [
            "pacman",
            "-Sp",
            "--config",
            str(config_path),
            "--print-format",
            "%n|%v|%r",
            "kitpro-linux-base",
        ]
    )
    if "kitpro-linux-base" not in resolution.stdout:
        raise PipelineError("isolated client did not resolve kitpro-linux-base")
    reconstruction = reconstruct(
        release,
        generation,
        repo_root,
        key_state,
        state_root / "reconstructed" / generation,
    )
    current = repo_root / "stable" / release / "current"
    if not current.is_symlink() or os.readlink(current) != generation:
        raise PipelineError("current does not point to the requested generation")
    return {
        "result": "passed",
        "release": release,
        "generation": generation,
        "promotion_artifact_hashes": hashes,
        "package_count": len(manifest["repositories"][0]["packages"]),
        "repository_database": manifest["repositories"][0]["database"],
        "key_roles": {role: entry["fingerprint"] for role, entry in keys["roles"].items()},
        "current_target": os.readlink(current),
        "reconstruction": reconstruction,
    }


def phase1(
    snapshot_date_value: str,
    release: str,
    generation: str,
    package_set_path: Path,
    repo_root: Path,
    state_root: Path,
    lock_output: Path | None,
) -> dict[str, Any]:
    key_state = state_root / "dev-keys"
    create_dev_keys(key_state)
    snapshot_root = ingest_snapshot(
        snapshot_date_value,
        package_set_path,
        repo_root,
        state_root,
        lock_output,
    )
    create_edge(snapshot_root, release, repo_root, state_root, key_state, package_set_path)
    promote(release, repo_root, key_state, "edge", "testing")
    publish(release, generation, repo_root, key_state)
    return verify_phase1(repo_root, state_root, release, generation)


def path_argument(value: str) -> Path:
    return Path(value).expanduser().resolve()


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser(description=__doc__)
    subcommands = main.add_subparsers(dest="command", required=True)

    validate_set = subcommands.add_parser("validate-package-set")
    validate_set.add_argument("path", type=path_argument)

    validate_generation = subcommands.add_parser("validate-manifest")
    validate_generation.add_argument("path", type=path_argument)

    keys = subcommands.add_parser("dev-keys")
    keys.add_argument("--state-dir", type=path_argument, required=True)
    keys.add_argument("--verify-only", action="store_true")

    ingest = subcommands.add_parser("ingest")
    ingest.add_argument("--snapshot-date", required=True)
    ingest.add_argument("--package-set", type=path_argument, required=True)
    ingest.add_argument("--repo-root", type=path_argument, required=True)
    ingest.add_argument("--state-dir", type=path_argument, default=(PROJECT_ROOT / ".state").resolve())
    ingest.add_argument("--lock-output", type=path_argument)

    edge = subcommands.add_parser("create-edge")
    edge.add_argument("--snapshot", type=path_argument, required=True)
    edge.add_argument("--release", required=True)
    edge.add_argument("--repo-root", type=path_argument, required=True)
    edge.add_argument("--state-dir", type=path_argument, default=(PROJECT_ROOT / ".state").resolve())
    edge.add_argument("--key-state", type=path_argument, default=(PROJECT_ROOT / ".state/dev-keys").resolve())
    edge.add_argument("--package-set", type=path_argument, default=(PROJECT_ROOT / "config/package-set.json").resolve())

    promotion = subcommands.add_parser("promote")
    promotion.add_argument("--source", required=True)
    promotion.add_argument("--target", required=True)
    promotion.add_argument("--release", required=True)
    promotion.add_argument("--repo-root", type=path_argument, required=True)
    promotion.add_argument("--key-state", type=path_argument, default=(PROJECT_ROOT / ".state/dev-keys").resolve())

    publication = subcommands.add_parser("publish")
    publication.add_argument("--release", required=True)
    publication.add_argument("--generation", required=True)
    publication.add_argument("--repo-root", type=path_argument, required=True)
    publication.add_argument("--key-state", type=path_argument, default=(PROJECT_ROOT / ".state/dev-keys").resolve())

    reconstruction = subcommands.add_parser("reconstruct")
    reconstruction.add_argument("--release", required=True)
    reconstruction.add_argument("--generation", required=True)
    reconstruction.add_argument("--repo-root", type=path_argument, required=True)
    reconstruction.add_argument("--key-state", type=path_argument, default=(PROJECT_ROOT / ".state/dev-keys").resolve())
    reconstruction.add_argument("--output", type=path_argument, required=True)

    verification = subcommands.add_parser("verify-phase1")
    verification.add_argument("--release", default="0.1-dev")
    verification.add_argument("--generation", default="0.1-dev-g0001")
    verification.add_argument("--repo-root", type=path_argument, required=True)
    verification.add_argument("--state-dir", type=path_argument, required=True)

    all_phase1 = subcommands.add_parser("phase1")
    all_phase1.add_argument("--snapshot-date", required=True)
    all_phase1.add_argument("--release", default="0.1-dev")
    all_phase1.add_argument("--generation", default="0.1-dev-g0001")
    all_phase1.add_argument("--package-set", type=path_argument, default=(PROJECT_ROOT / "config/package-set.json").resolve())
    all_phase1.add_argument("--repo-root", type=path_argument, default=(PROJECT_ROOT / "repo").resolve())
    all_phase1.add_argument("--state-dir", type=path_argument, default=(PROJECT_ROOT / ".state").resolve())
    all_phase1.add_argument("--lock-output", type=path_argument, default=(PROJECT_ROOT / "manifests/0.1-dev-package-lock.json").resolve())
    return main


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == "validate-package-set":
            validate_package_set(load_json(arguments.path))
            result: Any = {"result": "passed", "path": str(arguments.path)}
        elif arguments.command == "validate-manifest":
            validate_manifest(load_json(arguments.path))
            result = {"result": "passed", "path": str(arguments.path)}
        elif arguments.command == "dev-keys":
            result = create_dev_keys(arguments.state_dir, arguments.verify_only)
        elif arguments.command == "ingest":
            result = {
                "snapshot": str(
                    ingest_snapshot(
                        arguments.snapshot_date,
                        arguments.package_set,
                        arguments.repo_root,
                        arguments.state_dir,
                        arguments.lock_output,
                    )
                )
            }
        elif arguments.command == "create-edge":
            result = {
                "manifest": str(
                    create_edge(
                        arguments.snapshot,
                        arguments.release,
                        arguments.repo_root,
                        arguments.state_dir,
                        arguments.key_state,
                        arguments.package_set,
                    )
                )
            }
        elif arguments.command == "promote":
            result = {
                "manifest": str(
                    promote(
                        arguments.release,
                        arguments.repo_root,
                        arguments.key_state,
                        arguments.source,
                        arguments.target,
                    )
                )
            }
        elif arguments.command == "publish":
            result = {
                "manifest": str(
                    publish(
                        arguments.release,
                        arguments.generation,
                        arguments.repo_root,
                        arguments.key_state,
                    )
                )
            }
        elif arguments.command == "reconstruct":
            result = reconstruct(
                arguments.release,
                arguments.generation,
                arguments.repo_root,
                arguments.key_state,
                arguments.output,
            )
        elif arguments.command == "verify-phase1":
            result = verify_phase1(
                arguments.repo_root,
                arguments.state_dir,
                arguments.release,
                arguments.generation,
            )
        elif arguments.command == "phase1":
            result = phase1(
                arguments.snapshot_date,
                arguments.release,
                arguments.generation,
                arguments.package_set,
                arguments.repo_root,
                arguments.state_dir,
                arguments.lock_output,
            )
        else:
            raise PipelineError(f"unhandled command: {arguments.command}")
    except PipelineError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
