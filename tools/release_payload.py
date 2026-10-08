"""Prepare immutable public release-signing payloads from verified RC evidence."""
from __future__ import annotations

from pathlib import Path

from tools import kitpro_repo
from tools.production_media import GENERATION, release_identity


def prepare(source: Path, policy_path: Path, build_path: Path, static_path: Path,
            comparison_path: Path, output: Path, qualification_ids: dict) -> dict:
    identity = release_identity(source, policy_path)
    policy = identity['policy']
    build = kitpro_repo.load_json(build_path)
    static = kitpro_repo.load_json(static_path)
    comparison = kitpro_repo.load_json(comparison_path)
    iso = Path(build['iso_path'])
    digest = kitpro_repo.sha256_file(iso)
    if (iso.name != identity['filename'] or digest != build['iso_sha256']
            or static['iso_sha256'] != digest or static['status'] != 'passed'
            or comparison['first']['iso_sha256'] != digest
            or comparison['second']['iso_sha256'] != digest
            or static['source_metadata']['kind'] != 'production-iso'
            or static['source_metadata']['media_build_identity'] != identity['version']
            or static['sbom_schema_validation'] != 'passed'
            or not comparison['iso_bit_for_bit_identical']
            or not comparison['iso_sizes_identical']):
        raise kitpro_repo.PipelineError('release artifact qualification differs')
    commit = static['source_metadata']['source_git_commit']
    tree = kitpro_repo.run(['git', '-C', str(source), 'rev-parse', commit + '^{tree}']).stdout.strip()
    if set(qualification_ids) != {'tcg', 'kvm', 'beelink'} or not all(qualification_ids.values()):
        raise kitpro_repo.PipelineError('final qualification references are required before signing')
    sboms = static['sbom_sha256']
    for name, expected in sboms.items():
        if Path(name).name != name or kitpro_repo.sha256_file(static_path.parent / name) != expected:
            raise kitpro_repo.PipelineError('SBOM bytes differ')
    manifest = {
        'schema_version': 1, 'product': policy['product_name'], 'version': policy['product_version'],
        'rc_label': policy['rc_status'], 'source_commit': commit, 'source_tree': tree,
        'production_generation': GENERATION,
        'generation_manifest_sha256': policy['generation_manifest_sha256'],
        'iso_filename': iso.name, 'iso_size': iso.stat().st_size, 'iso_sha256': digest,
        'package_count': 199, 'explicit_package_count': 36, 'kernel': policy['kernel'],
        'installer_media_version': identity['version'], 'worker_lock_sha256': policy['worker_lock_sha256'],
        'fingerprints': policy['fingerprints'], 'sbom_sha256': sboms,
        'qualification_ids': qualification_ids, 'support': policy['support'],
        'build_timestamp_inputs': {'source_date_epoch': build['source_date_epoch'], 'timezone': 'UTC'},
    }
    # Immutable output: never overwrite a previously handed-off signing payload.
    output.mkdir(parents=True, exist_ok=False)
    for name in sboms:
        (output / name).write_bytes((static_path.parent / name).read_bytes())
    kitpro_repo.atomic_write_json(output / 'release-manifest.json', manifest)
    hashes = {iso.name: digest, **sboms,
              'release-manifest.json': kitpro_repo.sha256_file(output / 'release-manifest.json')}
    (output / 'SHA256SUMS').write_text(''.join(f'{value}  {name}\n' for name, value in sorted(hashes.items())))
    return manifest
