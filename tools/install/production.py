"""Pinned, offline production inputs for the whole-disk installation boundary."""
from __future__ import annotations

from pathlib import Path

from tools import kitpro_phase2, kitpro_repo, production_generation, production_identity
from tools.production_packages import FINGERPRINTS
from tools.production_publish import validate as validate_bytes
from tools.production_repository import production_pacman_config

PINS = {
    '1.0-g0001': 'e7a91a0c1453a890b81eb2f027bd24718c5f267beac11b2458244da6249eebb3',
    '1.0-g0002': 'fb20ff778fd2c4fcbd5cef72809d3104dcb5f0d81c196c708f0825cf60ee3585',
}
KEYRING_SHA256 = 'fb4e646f6112829acd5a5b13e148c73a1a2dfa63247fcb0f20361fd627cf463e'
ROOT = Path(__file__).resolve().parents[2]
TRUST = ROOT / '.state/production-verification'
PUBLIC_KEYRINGS = Path('/usr/share/pacman/keyrings')


def source(generation: str, repo: Path) -> tuple[Path, dict]:
    if generation not in PINS:
        raise kitpro_repo.PipelineError('production installation generation is not qualified')
    directory = repo / 'stable/1.0' / generation
    manifest = validate_bytes(directory, PINS[generation])
    if manifest['generation_id'] != generation:
        raise kitpro_repo.PipelineError('production generation identity mismatch')
    return directory, manifest


def prepare_trust(generation: str, repo: Path) -> Path:
    directory, manifest = source(generation, repo)
    record = next(p for p in manifest['packages'] if p['name'] == 'kitpro-linux-keyring')
    if record['sha256'] != KEYRING_SHA256:
        raise kitpro_repo.PipelineError('production trust bootstrap package changed')
    package = directory / 'core/os/x86_64' / record['filename']
    TRUST.mkdir(parents=True, exist_ok=True)
    # Public files embedded by the media builder must match the pinned package.
    # Never import host/operator trust or a signing home into the live client.
    for suffix in ('gpg', 'trusted', 'revoked'):
        name = 'kitpro-linux.' + suffix if suffix == 'gpg' else 'kitpro-linux-' + suffix
        installed = PUBLIC_KEYRINGS / name
        payload = kitpro_repo.run(['bsdtar', '-xOf', str(package), 'usr/share/pacman/keyrings/' + name], text=False).stdout
        if not installed.is_file() or installed.read_bytes() != payload:
            raise kitpro_repo.PipelineError('embedded production public trust differs from pinned package')
    # initialize_public_keyring is verification-only: it creates no secret key.
    for suffix in ('trusted', 'revoked'):
        names = [f'{name}-{suffix}' for name in ('archlinux', 'kitpro-linux')]
        (TRUST / suffix).write_bytes(b'\n'.join(
            (PUBLIC_KEYRINGS / name).read_bytes() for name in names
        ))
    home = TRUST / 'gnupg'
    # Import separately: the Arch keyring may be armored while KITPro's is
    # binary. Concatenating them can silently omit the second stream in GnuPG.
    rings = PUBLIC_KEYRINGS
    kitpro_repo.initialize_public_keyring(
        home, rings / 'kitpro-linux.gpg', TRUST / 'trusted', TRUST / 'revoked',
        additional_public_keyrings=(rings / 'archlinux.gpg',),
    )
    return home


def verify(generation: str, repo: Path) -> tuple[Path, dict]:
    directory, manifest = source(generation, repo)
    home = prepare_trust(generation, repo)
    packages = directory / 'core/os/x86_64'
    database = packages / manifest['database']['filename']
    signature = packages / (database.name + '.sig')
    if kitpro_repo.verify_signature(home, signature, database) != FINGERPRINTS['repository']:
        raise kitpro_repo.PipelineError('production repository signature authority mismatch')
    production_generation.validate_inventory(manifest, packages, home, home)
    return directory, manifest


def deploy(profile: dict, repo: Path, target: Path, scratch: Path, artifacts: Path) -> dict:
    directory, manifest = source(profile['generation'], repo)
    expected_explicit = sorted(p['name'] for p in manifest['packages'] if p['explicit'])
    if sorted(profile['explicit_packages']) != expected_explicit:
        raise kitpro_repo.PipelineError('production explicit package inventory mismatch')
    if not target.is_mount() or any(
        p.name not in {'lost+found', 'efi', '.kitpro-install-work'}
        or p.is_symlink() or not p.is_dir() for p in target.iterdir()
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
    text = production_pacman_config().replace(
        '[options]\n', f'[options]\nGPGDir = {gpg}\nCacheDir = {cache}\nLogFile = {scratch / "pacman.log"}\n'
    ).replace('https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/$arch',
              (directory / 'core/os/x86_64').resolve().as_uri())
    config.write_text(text)
    kitpro_phase2.run([
        str(kitpro_phase2.pacstrap_path(scratch)), '-G', '-M', '-C', str(config),
        str(target), *expected_explicit,
    ])
    installed = kitpro_phase2.installed_packages(target)
    if installed != {p['name']: p['version'] for p in manifest['packages']}:
        raise kitpro_repo.PipelineError('production installed inventory differs from pinned generation')
    explicit = kitpro_phase2.run([
        'pacman', '--root', str(target), '--dbpath', str(target / 'var/lib/pacman'), '-Qqe'
    ]).stdout.splitlines()
    if sorted(explicit) != expected_explicit:
        raise kitpro_repo.PipelineError('production installed package reasons differ')
    production_identity.update(target)
    if (target / 'etc/pacman.conf').read_text() != production_pacman_config():
        raise kitpro_repo.PipelineError('installed production repository configuration differs')
    for relative in ('efi/EFI/BOOT', 'efi/EFI/systemd', 'efi/loader/entries',
                     'etc/systemd/network', 'etc/systemd/journald.conf.d', 'var/log/journal'):
        (target / relative).mkdir(parents=True, exist_ok=True)
    kitpro_phase2.copy(ROOT / 'config/rootfs/mkinitcpio.conf', target / 'etc/mkinitcpio.conf')
    kitpro_phase2.copy(ROOT / 'config/rootfs/10-persistent.conf', target / 'etc/systemd/journald.conf.d/10-persistent.conf')
    efi = target / 'usr/lib/systemd/boot/efi/systemd-bootx64.efi'
    kitpro_phase2.copy(efi, target / 'efi/EFI/BOOT/BOOTX64.EFI')
    kitpro_phase2.copy(efi, target / 'efi/EFI/systemd/systemd-bootx64.efi')
    (target / 'efi/loader/loader.conf').write_text('default kitpro-linux.conf\ntimeout 3\nconsole-mode keep\n')
    (target / 'etc/machine-id').write_text('')
    kernel = next(p for p in manifest['packages'] if p['name'] == 'linux-lts')
    result = {
        'schema_version': 1, 'kitpro_release': '1.0', 'stable_generation': profile['generation'],
        'architecture': 'x86_64', 'resolved_package_count': len(installed),
        'explicit_packages': expected_explicit,
        'packages': [{k: p[k] for k in ('name', 'version', 'sha256')} for p in manifest['packages']],
        'kernel': {'package': 'linux-lts', 'version': kernel['version']},
        'initramfs': {'tool': 'mkinitcpio'},
        'build_tools': {'systemd': kitpro_phase2.command_version(['systemctl', '--version'])},
        'repository': {'generation_manifest_sha256': PINS[profile['generation']],
                       'artifact_set_sha256': manifest['artifact_set_sha256'],
                       'signature_policy': 'Required DatabaseRequired TrustedOnly'},
    }
    artifacts.mkdir(parents=True, exist_ok=True)
    kitpro_repo.atomic_write_json(artifacts / 'rootfs-manifest.json', result)
    return result
