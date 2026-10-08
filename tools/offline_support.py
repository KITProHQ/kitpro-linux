"""Safety boundary for rescue-mode support collection from an untrusted root."""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from tools import kitpro_repo


MOUNTINFO = Path("/proc/self/mountinfo")
MAX_JOURNAL_FILES = 512
MAX_JOURNAL_BYTES = 512 * 1024 * 1024
MAX_PACKAGE_ENTRIES = 4096
MAX_PACKAGE_DB_BYTES = 64 * 1024 * 1024
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_KERNEL_ARTIFACT_BYTES = 512 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9@._+:-]+$")


def _unescape_mount(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


@dataclass(frozen=True)
class MountRecord:
    mount_point: Path
    options: frozenset[str]
    filesystem: str
    source: str


def read_mountinfo(path: Path = MOUNTINFO) -> list[MountRecord]:
    records: list[MountRecord] = []
    for raw in path.read_text(errors="strict").splitlines():
        fields = raw.split()
        try:
            separator = fields.index("-")
        except ValueError as error:
            raise kitpro_repo.PipelineError("mountinfo contains an invalid record") from error
        if separator < 6 or len(fields) <= separator + 2:
            raise kitpro_repo.PipelineError("mountinfo contains an incomplete record")
        records.append(
            MountRecord(
                mount_point=Path(_unescape_mount(fields[4])),
                options=frozenset(fields[5].split(",")),
                filesystem=fields[separator + 1],
                source=_unescape_mount(fields[separator + 2]),
            )
        )
    return records


def _within(path: Path, parent: Path) -> bool:
    return path == parent or path.is_relative_to(parent)


def validate_mount_boundary(
    root: Path,
    esp: Path | None = None,
    mountinfo_path: Path = MOUNTINFO,
) -> dict[str, Any]:
    """Require explicit read-only mounts and reject unexpected nested mounts."""
    if root.is_symlink():
        raise kitpro_repo.PipelineError("rescue target root must not be a symlink")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise kitpro_repo.PipelineError("rescue target root is not a directory")
    esp_resolved: Path | None = None
    if esp is not None:
        if esp.is_symlink():
            raise kitpro_repo.PipelineError("rescue target ESP must not be a symlink")
        esp_resolved = esp.resolve(strict=True)
        if esp_resolved != root / "efi":
            raise kitpro_repo.PipelineError("explicit ESP must be mounted at TARGET/efi")

    records = read_mountinfo(mountinfo_path)
    exact = {record.mount_point.resolve(): record for record in records}
    root_record = exact.get(root)
    if root_record is None:
        raise kitpro_repo.PipelineError("target root must be an explicit mount point")
    if "ro" not in root_record.options or "rw" in root_record.options:
        raise kitpro_repo.PipelineError("target root must be mounted read-only")

    allowed = {root}
    esp_record: MountRecord | None = None
    if esp_resolved is not None:
        esp_record = exact.get(esp_resolved)
        if esp_record is None:
            raise kitpro_repo.PipelineError("target ESP must be an explicit mount point")
        if "ro" not in esp_record.options or "rw" in esp_record.options:
            raise kitpro_repo.PipelineError("target ESP must be mounted read-only")
        allowed.add(esp_resolved)

    nested = sorted(
        str(record.mount_point)
        for record in records
        if record.mount_point != root
        and _within(record.mount_point, root)
        and record.mount_point.resolve() not in allowed
    )
    if nested:
        raise kitpro_repo.PipelineError(
            f"unexpected nested mounts beneath target root: {nested}"
        )
    return {
        "root": str(root),
        "root_filesystem": root_record.filesystem,
        "root_source": root_record.source,
        "root_read_only": True,
        "esp": str(esp_resolved) if esp_resolved else None,
        "esp_filesystem": esp_record.filesystem if esp_record else None,
        "esp_source": esp_record.source if esp_record else None,
        "esp_read_only": True if esp_record else None,
    }


class SafeTargetReader:
    """Read files beneath a fixed root without following target symlinks."""

    def __init__(self, root: Path):
        self.root = root.resolve(strict=True)
        self._root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def close(self) -> None:
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "SafeTargetReader":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @staticmethod
    def _parts(relative: str | PurePosixPath) -> tuple[str, ...]:
        path = PurePosixPath(str(relative))
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise kitpro_repo.PipelineError(f"unsafe target-relative path: {relative}")
        return path.parts

    def _open_parent(self, parts: tuple[str, ...]) -> tuple[int, str]:
        descriptor = os.dup(self._root_fd)
        try:
            for component in parts[:-1]:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_fd
            return descriptor, parts[-1]
        except Exception:
            os.close(descriptor)
            raise

    def lstat(self, relative: str | PurePosixPath) -> os.stat_result:
        parts = self._parts(relative)
        parent_fd, name = self._open_parent(parts)
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)

    def read_bytes(self, relative: str | PurePosixPath, limit: int = 4 * 1024 * 1024) -> bytes:
        parts = self._parts(relative)
        parent_fd, name = self._open_parent(parts)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise kitpro_repo.PipelineError(f"target source is not a regular file: {relative}")
            if before.st_size > limit:
                raise kitpro_repo.PipelineError(f"target source exceeds safety limit: {relative}")
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(descriptor, min(131072, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            after = os.fstat(descriptor)
            if len(value) > limit:
                raise kitpro_repo.PipelineError(f"target source exceeds safety limit: {relative}")
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise kitpro_repo.PipelineError(f"target source changed during collection: {relative}")
            return value
        finally:
            os.close(descriptor)

    def read_json(self, relative: str | PurePosixPath) -> dict[str, Any]:
        try:
            value = json.loads(self.read_bytes(relative).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise kitpro_repo.PipelineError(f"target JSON is invalid: {relative}") from error
        if not isinstance(value, dict):
            raise kitpro_repo.PipelineError(f"target JSON is not an object: {relative}")
        return value

    def list_names(self, relative: str | PurePosixPath) -> list[str]:
        descriptor = self.open_directory(relative)
        try:
            names = sorted(os.listdir(descriptor))
        finally:
            os.close(descriptor)
        if any(name in {".", ".."} or "/" in name for name in names):
            raise kitpro_repo.PipelineError(f"target directory has an unsafe entry: {relative}")
        return names

    def open_directory(self, relative: str | PurePosixPath) -> int:
        parts = self._parts(relative)
        descriptor = os.dup(self._root_fd)
        try:
            for component in parts:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_fd
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def validate_relative_symlink(
        self,
        relative: str,
        allowed_target: str | None = None,
        require_exists: bool = True,
    ) -> str:
        parts = self._parts(relative)
        parent_fd, name = self._open_parent(parts)
        try:
            target = os.readlink(name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        if allowed_target is not None and target != allowed_target:
            raise kitpro_repo.PipelineError(f"target symlink has an unsupported destination: {relative}")
        if PurePosixPath(target).is_absolute():
            raise kitpro_repo.PipelineError(f"absolute target symlink is not allowed: {relative}")
        normalized = PurePosixPath(*PurePosixPath(relative).parent.parts, *PurePosixPath(target).parts)
        depth = 0
        clean: list[str] = []
        for part in normalized.parts:
            if part == "..":
                if not clean:
                    raise kitpro_repo.PipelineError(f"target symlink escapes root: {relative}")
                clean.pop()
            elif part not in {"", "."}:
                clean.append(part)
            depth = len(clean)
        if depth == 0:
            raise kitpro_repo.PipelineError(f"target symlink resolves to root: {relative}")
        if require_exists:
            self.lstat(PurePosixPath(*clean))
        return target


def _optional(reader: SafeTargetReader, relative: str) -> bool:
    try:
        reader.lstat(relative)
        return True
    except FileNotFoundError:
        return False


def _validate_regular(reader: SafeTargetReader, relative: str, required: bool = False) -> None:
    try:
        metadata = reader.lstat(relative)
    except FileNotFoundError:
        if required:
            raise kitpro_repo.PipelineError(f"required target source is missing: {relative}")
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise kitpro_repo.PipelineError(f"target source is not a regular file: {relative}")


def _validate_directory_files(
    reader: SafeTargetReader,
    relative: str,
    suffix: str,
    maximum: int,
) -> None:
    try:
        names = reader.list_names(relative)
    except FileNotFoundError:
        return
    selected = [name for name in names if name.endswith(suffix)]
    if len(selected) > maximum:
        raise kitpro_repo.PipelineError(f"too many eligible target files beneath {relative}")
    for name in selected:
        if not SAFE_NAME.fullmatch(name):
            raise kitpro_repo.PipelineError(f"unsafe target filename beneath {relative}")
        _validate_regular(reader, f"{relative}/{name}")
        reader.read_bytes(f"{relative}/{name}", MAX_TEXT_BYTES)


def _validate_package_database(reader: SafeTargetReader) -> int:
    try:
        names = reader.list_names("var/lib/pacman/local")
    except FileNotFoundError as error:
        raise kitpro_repo.PipelineError("target package database is missing") from error
    if len(names) > MAX_PACKAGE_ENTRIES:
        raise kitpro_repo.PipelineError("target package database exceeds entry limit")
    count = 0
    total = 0
    for name in names:
        if not SAFE_NAME.fullmatch(name):
            raise kitpro_repo.PipelineError("target package database has an unsafe entry")
        relative = f"var/lib/pacman/local/{name}"
        metadata = reader.lstat(relative)
        if name == "ALPM_DB_VERSION":
            if not stat.S_ISREG(metadata.st_mode):
                raise kitpro_repo.PipelineError("target package database version is not a regular file")
            total += metadata.st_size
            reader.read_bytes(relative, MAX_TEXT_BYTES)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise kitpro_repo.PipelineError("target package database has an unsupported entry")
        descriptor = reader.open_directory(relative)
        os.close(descriptor)
        desc = f"var/lib/pacman/local/{name}/desc"
        metadata = reader.lstat(desc)
        if not stat.S_ISREG(metadata.st_mode):
            raise kitpro_repo.PipelineError("target package description is not a regular file")
        total += metadata.st_size
        if total > MAX_PACKAGE_DB_BYTES:
            raise kitpro_repo.PipelineError("target package database exceeds size limit")
        try:
            description = reader.read_bytes(desc, MAX_TEXT_BYTES).decode("utf-8")
        except UnicodeDecodeError as error:
            raise kitpro_repo.PipelineError("target package description is not UTF-8") from error
        if not re.search(r"(?m)^%NAME%\n[^\n]+$", description) or not re.search(
            r"(?m)^%VERSION%\n[^\n]+$", description
        ):
            raise kitpro_repo.PipelineError(
                "target package description is missing NAME or VERSION"
            )
        count += 1
    return count


def _validate_journal_tree(reader: SafeTargetReader) -> dict[str, int | bool]:
    base = reader.root / "var/log/journal"
    try:
        descriptor = reader.open_directory("var/log/journal")
        os.close(descriptor)
    except FileNotFoundError:
        return {"present": False, "files": 0, "bytes": 0}
    entries = 0
    files = 0
    total = 0
    for current, directories, filenames in os.walk(base, followlinks=False):
        current_path = Path(current)
        if current_path.is_symlink():
            raise kitpro_repo.PipelineError("journal tree contains a symlink directory")
        for name in [*directories, *filenames]:
            entries += 1
            if entries > MAX_JOURNAL_FILES:
                raise kitpro_repo.PipelineError("journal tree exceeds entry limit")
            item = current_path / name
            metadata = item.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise kitpro_repo.PipelineError("journal tree contains a symlink")
            if stat.S_ISREG(metadata.st_mode):
                files += 1
                total += metadata.st_size
                if total > MAX_JOURNAL_BYTES:
                    raise kitpro_repo.PipelineError("journal tree exceeds offline collection safety limits")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise kitpro_repo.PipelineError("journal tree contains an unsupported file type")
    return {"present": True, "files": files, "bytes": total}


def validate_target_surface(root: Path) -> dict[str, Any]:
    """Validate every target-controlled path used by offline bundle collection."""
    with SafeTargetReader(root) as reader:
        try:
            os_release = reader.lstat("etc/os-release")
        except FileNotFoundError as error:
            raise kitpro_repo.PipelineError("target OS identity is missing") from error
        if stat.S_ISLNK(os_release.st_mode):
            reader.validate_relative_symlink("etc/os-release", "../usr/lib/os-release")
            reader.read_bytes("usr/lib/os-release")
        elif stat.S_ISREG(os_release.st_mode):
            reader.read_bytes("etc/os-release")
        else:
            raise kitpro_repo.PipelineError("target OS identity is not a regular file")

        for relative in (
            "etc/kitpro-linux-release.json", "etc/hostname", "etc/passwd",
            "etc/pacman.conf", "etc/fstab", "etc/nftables.conf",
            "etc/ssh/sshd_config.d/10-kitpro-server.conf",
            "efi/loader/loader.conf", "var/lib/kitpro-linux/kernel-state.json",
            "var/lib/kitpro-linux/install-receipt.json", "etc/kitpro-installation.json",
        ):
            _validate_regular(reader, relative, required=relative == "etc/pacman.conf")
            if _optional(reader, relative):
                reader.read_bytes(relative, MAX_TEXT_BYTES)

        if _optional(reader, "etc/resolv.conf"):
            metadata = reader.lstat("etc/resolv.conf")
            if stat.S_ISLNK(metadata.st_mode):
                reader.validate_relative_symlink(
                    "etc/resolv.conf",
                    "../run/systemd/resolve/stub-resolv.conf",
                    require_exists=False,
                )
            elif not stat.S_ISREG(metadata.st_mode):
                raise kitpro_repo.PipelineError("target resolv.conf has an unsupported type")

        _validate_directory_files(reader, "etc/systemd/network", ".network", 20)
        _validate_directory_files(reader, "efi/loader/entries", ".conf", 32)
        _validate_directory_files(reader, "var/lib/kitpro-linux/kernel-transitions", ".json", 256)
        _validate_directory_files(reader, "var/lib/kitpro-linux/recovery", ".json", 256)
        packages = _validate_package_database(reader)

        state: dict[str, Any] = {}
        if _optional(reader, "var/lib/kitpro-linux/kernel-state.json"):
            state = reader.read_json("var/lib/kitpro-linux/kernel-state.json")
            for key in (
                "current_kernel_image_path", "current_initramfs_path", "current_module_tree",
                "current_boot_entry", "previous_kernel_image_path", "previous_initramfs_path",
                "previous_module_tree", "previous_boot_entry",
            ):
                value = state.get(key)
                if not value:
                    continue
                if not isinstance(value, str) or not value.startswith("/") or ".." in PurePosixPath(value).parts:
                    raise kitpro_repo.PipelineError(f"kernel-state path is unsafe: {key}")
                relative = value.removeprefix("/")
                try:
                    metadata = reader.lstat(relative)
                except FileNotFoundError:
                    # Missing boot artifacts are diagnostic state, not a
                    # confinement failure. The health report records them.
                    continue
                if key.endswith("module_tree"):
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise kitpro_repo.PipelineError(f"kernel-state module path is invalid: {key}")
                    _validate_regular(reader, f"{relative}/pkgbase", required=True)
                    _validate_regular(reader, f"{relative}/vmlinuz", required=True)
                elif not stat.S_ISREG(metadata.st_mode):
                    raise kitpro_repo.PipelineError(f"kernel-state artifact path is invalid: {key}")
                elif metadata.st_size > MAX_KERNEL_ARTIFACT_BYTES:
                    raise kitpro_repo.PipelineError(f"kernel-state artifact exceeds size limit: {key}")

            transition_receipt = state.get("transition_receipt")
            if transition_receipt:
                if (
                    not isinstance(transition_receipt, str)
                    or not transition_receipt.startswith("/var/lib/kitpro-linux/kernel-transitions/")
                    or ".." in PurePosixPath(transition_receipt).parts
                ):
                    raise kitpro_repo.PipelineError("kernel-state transition receipt path is unsafe")
                _validate_regular(reader, transition_receipt.removeprefix("/"))

        journal = _validate_journal_tree(reader)
        return {
            "package_entries": packages,
            "journal": journal,
            "kernel_state_present": bool(state),
            "target_surface": "validated",
        }


def validate_output_destination(output: Path, roots: Iterable[Path]) -> Path:
    if not output.is_absolute() or output.suffixes[-2:] != [".tar", ".zst"]:
        raise kitpro_repo.PipelineError("support bundle output must be an absolute .tar.zst path")
    parent = output.parent.resolve(strict=True)
    resolved = parent / output.name
    for root in roots:
        boundary = root.resolve(strict=True)
        if _within(resolved, boundary):
            raise kitpro_repo.PipelineError("support bundle output must be outside the target filesystems")
    return resolved
