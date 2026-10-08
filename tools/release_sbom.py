"""Deterministic package-level SPDX inventories, with no inferred license claims."""
from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

from tools import kitpro_repo

SCHEMA = Path(__file__).resolve().parents[1] / 'schemas/vendor/spdx-2.3.schema.json'


def document(name: str, packages: list[dict], epoch: int, identity: str) -> dict:
    if not packages or len({p['name'] for p in packages}) != len(packages):
        raise ValueError('package inventory must be nonempty and unique')
    records = []
    for package in sorted(packages, key=lambda item: item['name']):
        if not re.fullmatch(r'[a-zA-Z0-9.+_-]+', package['name']):
            raise ValueError('invalid package name')
        if not re.fullmatch(r'[0-9a-f]{64}', package['sha256']):
            raise ValueError('invalid package checksum')
        records.append({
            'SPDXID': 'SPDXRef-Package-' + package['name'].replace('_', '-'),
            'name': package['name'], 'versionInfo': package['version'],
            'downloadLocation': package.get('download_url', 'NOASSERTION'),
            'filesAnalyzed': False, 'licenseConcluded': 'NOASSERTION',
            'licenseDeclared': 'NOASSERTION', 'copyrightText': 'NOASSERTION',
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': package['sha256']}],
        })
    ids = [record['SPDXID'] for record in records]
    if len(set(ids)) != len(ids):
        raise ValueError('SPDX package identifier collision')
    result = {
        'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
        'SPDXID': 'SPDXRef-DOCUMENT', 'name': name,
        'documentNamespace': 'https://kitpro.us/spdx/' + identity,
        'creationInfo': {
            'created': dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'creators': ['Tool: kitpro-release-sbom-1'],
            'comment': 'Package archive inventory. File-level and license analysis are not asserted.',
        },
        'documentDescribes': ids, 'packages': records,
        'relationships': [{'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES',
                           'relatedSpdxElement': identifier} for identifier in ids],
    }
    return result


def live_packages(root: Path, cache: Path) -> list[dict]:
    result = []
    for path in sorted((root / 'var/lib/pacman/local').glob('*/desc')):
        fields = {part.splitlines()[0]: part.splitlines()[1:]
                  for part in path.read_text().split('\n\n') if part.strip()}
        name, version = fields['%NAME%'][0], fields['%VERSION%'][0]
        archives = list(cache.glob(f'{name}-{version}-*.pkg.tar.zst'))
        if len(archives) != 1:
            raise ValueError('live package archive missing or ambiguous: ' + name)
        result.append(dict(name=name, version=version, sha256=kitpro_repo.sha256_file(archives[0])))
    return result


def write_media_sboms(root: Path, cache: Path, manifest: dict, iso_sha256: str, output: Path) -> dict:
    epoch = manifest['source']['epoch']
    inventories = {
        'iso-packages.spdx.json': document('KITPro Linux Server live installer packages',
                                         live_packages(root, cache), epoch, iso_sha256 + '-live'),
        'production-generation.spdx.json': document('KITPro Linux Server ' + manifest['generation_id'],
                                                    manifest['packages'], epoch,
                                                    manifest['artifact_set_sha256'] + '-generation'),
    }
    hashes = {}
    for name, value in inventories.items():
        kitpro_repo.atomic_write_json(output / name, value)
        hashes[name] = kitpro_repo.sha256_file(output / name)
    return hashes
