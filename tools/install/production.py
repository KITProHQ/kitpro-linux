"""Pinned, offline production inputs for the whole-disk installation boundary."""
from __future__ import annotations

from pathlib import Path

from tools import (
    generation_descriptor,
    kitpro_phase2,
    kitpro_repo,
    production_generation,
    production_identity,
    release_repository,
)
from tools.production_packages import FINGERPRINTS
from tools.production_publish import validate as validate_bytes
from tools.production_repository import production_pacman_config

PINS = {
    '1.0-g0001': 'e7a91a0c1453a890b81eb2f027bd24718c5f267beac11b2458244da6249eebb3',
    '1.0-g0002': 'fb20ff778fd2c4fcbd5cef72809d3104dcb5f0d81c196c708f0825cf60ee3585',
    '1.1-g0001': '83e10d510c15d906a86c3e0f403cdc468281cb891c7364759a08572db9848fec',
}
RELEASES = {'1.0-g0001': '1.0', '1.0-g0002': '1.0', '1.1-g0001': '1.1'}
KEYRING_SHA256 = 'fb4e646f6112829acd5a5b13e148c73a1a2dfa63247fcb0f20361fd627cf463e'
ROOT = Path(__file__).resolve().parents[2]
TRUST = ROOT / '.state/production-verification'
PUBLIC_KEYRINGS = Path('/usr/share/pacman/keyrings')


def packages(manifest: dict) -> list[dict]:
    """Return the package closure from either supported production manifest shape."""
    if 'repositories' in manifest:
        repositories = manifest['repositories']
        if len(repositories) != 1:
            raise kitpro_repo.PipelineError('production repository count differs')
        return repositories[0]['packages']
    return manifest['packages']


def artifact_set_sha256(manifest: dict) -> str:
    """Return the canonical package-byte commitment for a production generation."""
    value = manifest.get('artifact_set_sha256')
    return value if value is not None else kitpro_repo.artifact_set_hash(packages(manifest))


def pacman_config(generation: str) -> str:
    """Return the immutable release's canonical installed Pacman configuration."""
    release = RELEASES[generation]
    if release == '1.0':
        return production_pacman_config()
    return release_repository.production_pacman_config(
        release_repository.release_config(release)
    )


def source(generation: str, repo: Path) -> tuple[Path, dict]:
    if generation not in PINS:
        raise kitpro_repo.PipelineError('production installation generation is not qualified')
    directory = repo / f"stable/{RELEASES[generation]}" / generation
    manifest_path = directory / 'manifest.json'
    if not manifest_path.is_file() or kitpro_repo.sha256_file(manifest_path) != PINS[generation]:
        raise kitpro_repo.PipelineError('production generation manifest changed')
    manifest = kitpro_repo.load_json(manifest_path)
    if RELEASES[generation] == '1.0':
        manifest = validate_bytes(directory, PINS[generation])
    if manifest['generation_id'] != generation:
        raise kitpro_repo.PipelineError('production generation identity mismatch')
    return directory, manifest


def prepare_trust(generation: str, repo: Path) -> Path:
    directory, manifest = source(generation, repo)
    packages = manifest.get('packages') or manifest['repositories'][0]['packages']
    record = next(p for p in packages if p['name'] == 'kitpro-linux-keyring')
    if record['sha256'] != KEYRING_SHA256:
        raise kitpro_repo.PipelineError('production trust bootstrap package changed')
    package_root = directory / 'core/os/x86_64'
    package = package_root / record['filename']
    arch_record = next(p for p in packages if p['name'] == 'archlinux-keyring')
    arch_package = package_root / arch_record['filename']
    TRUST.mkdir(parents=True, exist_ok=True)
    # Derive public trust only from the exact signed generation packages. Never
    # import host/operator trust or a signing home into the live client.
    extracted: dict[str, bytes] = {}
    for prefix, artifact in (('kitpro-linux', package), ('archlinux', arch_package)):
        for suffix in ('gpg', 'trusted', 'revoked'):
            name = f'{prefix}.{suffix}' if suffix == 'gpg' else f'{prefix}-{suffix}'
            extracted[name] = kitpro_repo.package_member(
                artifact, 'usr/share/pacman/keyrings/' + name
            )
    for suffix in ('trusted', 'revoked'):
        (TRUST / suffix).write_bytes(
            b'\n'.join(extracted[f'{name}-{suffix}'] for name in ('archlinux', 'kitpro-linux'))
        )
    for name in ('kitpro-linux.gpg', 'archlinux.gpg'):
        (TRUST / name).write_bytes(extracted[name])
    home = TRUST / 'gnupg'
    # Import separately: the Arch keyring may be armored while KITPro's is
    # binary. Concatenating them can silently omit the second stream in GnuPG.
    kitpro_repo.initialize_public_keyring(
        home,
        TRUST / 'kitpro-linux.gpg',
        TRUST / 'trusted',
        TRUST / 'revoked',
        additional_public_keyrings=(TRUST / 'archlinux.gpg',),
    )
    return home


def verify(generation: str, repo: Path) -> tuple[Path, dict]:
    directory, manifest = source(generation, repo)
    home = prepare_trust(generation, repo)
    packages = directory / 'core/os/x86_64'
    repository = manifest['repositories'][0] if 'repositories' in manifest else manifest
    database = packages / repository['database']['filename']
    signature = packages / (database.name + '.sig')
    if kitpro_repo.verify_signature(home, signature, database) != FINGERPRINTS['repository']:
        raise kitpro_repo.PipelineError('production repository signature authority mismatch')
    if RELEASES[generation] == '1.0':
        production_generation.validate_inventory(manifest, packages, home, home)
    else:
        records = repository['packages']
        if len(records) != 199 or sum(item['explicit'] is True for item in records) != 36:
            raise kitpro_repo.PipelineError('production package closure differs')
        for record in records:
            artifact = packages / record['filename']
            detached = packages / record['signature_filename']
            if (
                not artifact.is_file()
                or kitpro_repo.sha256_file(artifact) != record['sha256']
                or not detached.is_file()
                or kitpro_repo.sha256_file(detached) != record['signature_sha256']
            ):
                raise kitpro_repo.PipelineError(f"production package changed: {record['name']}")
        descriptor = manifest.get('generation_descriptor', {})
        generation_descriptor.validate_database(
            database,
            expected_member=descriptor.get('member', ''),
            expected_descriptor=descriptor.get('value', {}),
            packages=records,
            package_directory=packages,
        )
    return directory, manifest


def deploy(profile: dict, repo: Path, target: Path, scratch: Path, artifacts: Path,
           *, allowed_mountpoints: frozenset[str] = frozenset(), preserve_esp: bool = False) -> dict:
    directory, manifest = source(profile['generation'], repo)
    package_records = packages(manifest)
    expected_explicit = sorted(p['name'] for p in package_records if p['explicit'])
    if sorted(profile['explicit_packages']) != expected_explicit:
        raise kitpro_repo.PipelineError('production explicit package inventory mismatch')
    allowed = {'lost+found', 'efi', '.kitpro-install-work', *allowed_mountpoints}
    if not target.is_mount() or any(
        p.name not in allowed or p.is_symlink() or not p.is_dir()
        or (p.name in allowed_mountpoints and not p.is_mount()) for p in target.iterdir()
    ):
        raise kitpro_repo.PipelineError('production deployment requires an empty mounted target')
    cache = scratch / 'cache'
    cache.mkdir()
    gpg = target / 'etc/pacman.d/gnupg'
    gpg.mkdir(parents=True)
    # Each installed client owns its own local pacman certification key. It is
    # generated on this target, never embedded in media or imported from a signer.
    kitpro_repo.run(['pacman-key', '--gpgdir', str(gpg), '--init'])
    kitpro_repo.run(['pacman-key', '--gpgdir', str(gpg), '--populate', 'archlinux', 'kitpro-linux'])
    config = scratch / 'pacman.conf'
    installed_pacman_config = pacman_config(profile['generation'])
    text = installed_pacman_config.replace(
        '[options]\n', f'[options]\nGPGDir = {gpg}\nCacheDir = {cache}\nLogFile = {scratch / "pacman.log"}\n'
    ).replace(profile['repository_url'], (directory / 'core/os/x86_64').resolve().as_uri())
    config.write_text(text)
    kitpro_phase2.run([
        str(kitpro_phase2.pacstrap_path(scratch)), '-G', '-M', '-C', str(config),
        str(target), *expected_explicit,
    ])
    installed = kitpro_phase2.installed_packages(target)
    if installed != {p['name']: p['version'] for p in package_records}:
        raise kitpro_repo.PipelineError('production installed inventory differs from pinned generation')
    explicit = kitpro_phase2.run([
        'pacman', '--root', str(target), '--dbpath', str(target / 'var/lib/pacman'), '-Qqe'
    ]).stdout.splitlines()
    if sorted(explicit) != expected_explicit:
        raise kitpro_repo.PipelineError('production installed package reasons differ')
    production_identity.update(target)
    if (target / 'etc/pacman.conf').read_text() != installed_pacman_config:
        raise kitpro_repo.PipelineError('installed production repository configuration differs')
    efi_directories = (
        ('efi/EFI/KITPRO', 'efi/loader/entries')
        if preserve_esp
        else ('efi/EFI/BOOT', 'efi/EFI/systemd', 'efi/loader/entries')
    )
    for relative in (*efi_directories,
                     'etc/systemd/network', 'etc/systemd/journald.conf.d', 'var/log/journal'):
        (target / relative).mkdir(parents=True, exist_ok=True)
    kitpro_phase2.copy(ROOT / 'config/rootfs/mkinitcpio.conf', target / 'etc/mkinitcpio.conf')
    kitpro_phase2.copy(ROOT / 'config/rootfs/10-persistent.conf', target / 'etc/systemd/journald.conf.d/10-persistent.conf')
    efi = target / 'usr/lib/systemd/boot/efi/systemd-bootx64.efi'
    if preserve_esp:
        kitpro_phase2.copy(efi, target / 'efi/EFI/KITPRO/kitpro-bootx64.efi')
    else:
        kitpro_phase2.copy(efi, target / 'efi/EFI/BOOT/BOOTX64.EFI')
        kitpro_phase2.copy(efi, target / 'efi/EFI/systemd/systemd-bootx64.efi')
    (target / 'efi/loader/loader.conf').write_text('default kitpro-linux.conf\ntimeout 3\nconsole-mode keep\n')
    (target / 'etc/machine-id').write_text('')
    kernel = next(p for p in package_records if p['name'] == 'linux-lts')
    result = {
        'schema_version': 1, 'kitpro_release': profile['release'],
        'stable_generation': profile['generation'],
        'architecture': 'x86_64', 'resolved_package_count': len(installed),
        'explicit_packages': expected_explicit,
        'packages': [{k: p[k] for k in ('name', 'version', 'sha256')} for p in package_records],
        'kernel': {'package': 'linux-lts', 'version': kernel['version']},
        'initramfs': {'tool': 'mkinitcpio'},
        'build_tools': {'systemd': kitpro_phase2.command_version(['systemctl', '--version'])},
        'repository': {'generation_manifest_sha256': PINS[profile['generation']],
                       'artifact_set_sha256': artifact_set_sha256(manifest),
                       'signature_policy': 'Required DatabaseRequired TrustedOnly'},
    }
    artifacts.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(artifacts / 'rootfs-manifest.json', result)
    return result
