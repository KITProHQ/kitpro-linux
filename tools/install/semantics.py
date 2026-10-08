"""Read-only filesystem semantics inventory for installation qualification."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
from pathlib import Path


def inventory(root: Path, prefixes: list[str]) -> dict:
    records = {}
    links = {}
    for prefix in prefixes:
        start = root / prefix
        if not start.exists():
            raise ValueError('inventory prefix missing: ' + prefix)
        paths = [start]
        for directory, dirs, files in os.walk(start, followlinks=False):
            paths.extend(Path(directory) / name for name in sorted(dirs + files))
        for path in paths:
            relative = path.relative_to(root).as_posix()
            if relative in records:
                continue
            metadata = path.lstat()
            row = {
                'mode': stat.S_IMODE(metadata.st_mode), 'uid': metadata.st_uid,
                'gid': metadata.st_gid, 'kind': stat.S_IFMT(metadata.st_mode),
            }
            if stat.S_ISREG(metadata.st_mode):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                row.update(sha256=digest.hexdigest(), size=metadata.st_size,
                           mtime_ns=metadata.st_mtime_ns)
                if metadata.st_nlink > 1:
                    links.setdefault((metadata.st_dev, metadata.st_ino), []).append(relative)
            elif stat.S_ISLNK(metadata.st_mode):
                row['target'] = os.readlink(path)
            elif stat.S_ISCHR(metadata.st_mode) or stat.S_ISBLK(metadata.st_mode):
                row['rdev'] = metadata.st_rdev
            row['xattrs'] = {
                name: base64.b64encode(os.getxattr(path, name, follow_symlinks=False)).decode()
                for name in sorted(os.listxattr(path, follow_symlinks=False))
            }
            records[relative] = row
    return {
        'schema_version': 1, 'records': records,
        'hardlink_groups': sorted(sorted(group) for group in links.values() if len(group) > 1),
        'directory_mtime_policy': 'not compared; directory timestamps reflect configuration writes',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--prefix', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(inventory(args.root, args.prefix), sort_keys=True) + '\n')
