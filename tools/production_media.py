"""Construct pinned production media with explicit release or qualification identity."""
from __future__ import annotations

import argparse
import ast
import json
import re
import shutil
from pathlib import Path

from tools import kitpro_repo, phase4_media, phase5
from tools.install.production import KEYRING_SHA256, PINS
from tools.install.receipt import load_source_metadata
from tools.production_publish import validate as validate_generation
from tools.production_repository import production_pacman_config

GENERATION = '1.0-g0002'
VERSION = '1.0-memory-qualification'
ISO_NAME = f'kitpro-linux-server-{VERSION}-x86_64.iso'
RUNTIME_MODULES = (
    '__init__.py', 'kitpro_repo.py', 'kitpro_phase2.py', 'guided_installer.py',
    'rescue.py', 'offline_support.py', 'phase4_live.py', 'system_health.py',
    'support_bundle.py', 'support_bundle_inspect.py', 'production_generation.py',
    'production_identity.py', 'production_packages.py', 'production_publish.py',
    'production_repository.py',
)


def release_identity(source: Path, policy_path: Path | None = None) -> dict:
    if policy_path is None:
        return dict(version=VERSION, filename=ISO_NAME, status='Memory Qualification',
                    kind='developer-iso', label='KITPRO_MEM_1_0', qualification_only=True)
    policy = kitpro_repo.load_json(policy_path)
    from tools.production_packages import FINGERPRINTS
    expected = {
        'product_name': 'KITPro Linux Server', 'product_version': '1.0',
        'repository_release': '1.0', 'repository_generation': GENERATION,
        'generation_manifest_sha256': PINS[GENERATION],
        'worker_lock_sha256': kitpro_repo.sha256_file(source / 'ci/worker-lock.json'),
        'package_count': 199, 'explicit_package_count': 36, 'squashfs_processors': 4,
        'fingerprints': FINGERPRINTS,
    }
    if any(policy.get(key) != value for key, value in expected.items()):
        raise kitpro_repo.PipelineError('release policy differs from pinned production inputs')
    version = policy['media_build_identity']
    if (not re.fullmatch(r'1\.0-rc[1-9][0-9]*', version)
            or policy['release_status'] != version.split('-')[1].upper()
            or policy['iso_filename'] != f'kitpro-linux-server-{version}-x86_64.iso'):
        raise kitpro_repo.PipelineError('invalid release identity')
    return dict(version=version, filename=policy['iso_filename'], status=policy['release_status'],
                kind='production-iso', label='KITPRO_' + version.upper().replace('.', '_').replace('-', '_'),
                qualification_only=False, policy=policy)


PRESENTATION_PATTERN = re.compile(
    r'development|developer|pre-release installation media|0\.1-dev|g000[789]|g0010'
    r'|\bphase[\s._-]*[0-9]|\balpha\b|[0-9]\.[0-9][^\s]*-dev', re.I)


def validate_presentation(live: Path, entries: Path) -> None:
    """Inspect console text and Python output/error literals before freezing media."""
    def check(text: str, path: Path) -> None:
        if PRESENTATION_PATTERN.search(text):
            raise kitpro_repo.PipelineError('development presentation remains in ' + path.name)

    for path in [live / 'etc/motd', live / 'etc/os-release', *entries.glob('*.conf')]:
        if path.is_file():
            check(path.read_text(), path)
    # Shell control identifiers and comments are not rendered UI. Inspect output
    # statements and prompts, including explicit acceptance serial handshakes.
    shells = [live / 'root/.bash_profile']
    shells.extend((live / 'usr/local/bin').glob('*'))
    shells.extend((live / 'usr/local/lib/kitpro-linux').glob('*'))
    for path in shells:
        if path.is_file():
            for line in path.read_text().splitlines():
                if re.search(r'\b(?:printf|echo)\b|\bread\b.*-[^ ]*p', line) and not line.lstrip().startswith('#'):
                    check(line, path)
    tools = live / 'opt/kitpro-linux/tools'
    sources = [tools / name for name in ('guided_installer.py', 'rescue.py', 'phase4_live.py')]
    sources.extend((tools / 'install').glob('*.py'))
    for path in sources:
        if not path.is_file():
            continue
        tree = ast.parse(path.read_text())
        if path.name in {'__main__.py', 'guided_installer.py', 'rescue.py', 'phase4_live.py'}:
            check(ast.get_docstring(tree) or '', path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, 'id', getattr(node.func, 'attr', ''))
            if name not in {'print', 'write', 'ask', 'PipelineError', 'ArgumentParser', 'add_argument'}:
                continue
            # Nested function calls can contain internal filenames; inspect only
            # literals and interpolated string fragments directly sent to output.
            for value in [*node.args, *(item.value for item in node.keywords)]:
                fragments = value.values if isinstance(value, ast.JoinedStr) else [value]
                for fragment in fragments:
                    if isinstance(fragment, ast.Constant) and isinstance(fragment.value, str):
                        check(fragment.value, path)


def stage_qualification_profile(source: Path, generation: Path, run: Path,
                                release_policy: Path | None = None) -> tuple[Path, dict]:
    commit, dirty = phase5._git_state(source)
    if dirty:
        raise kitpro_repo.PipelineError('qualification media requires a clean source commit')
    identity = release_identity(source, release_policy)
    version, status = identity['version'], identity['status']
    manifest = validate_generation(generation, PINS[GENERATION])
    if release_policy is not None and (
            manifest['artifact_set_sha256'] != identity['policy']['artifact_set_sha256']
            or manifest['kernel_version'] != identity['policy']['kernel']):
        raise kitpro_repo.PipelineError('release policy generation content differs')
    if manifest['generation_id'] != GENERATION:
        raise kitpro_repo.PipelineError('qualification media must install production g0002')
    profile_source = source / 'archiso/kitpro-developer'
    phase4_media.validate_profile_inputs(profile_source, source)
    profile = run / 'profile'
    shutil.copytree(profile_source, profile, symlinks=True)
    definition = profile / 'profiledef.sh'
    text = definition.read_text().replace('KITPRO_0_8_DEV', identity['label'])
    text = text.replace('0.8.0-dev.18', version).replace(
        'KITPro Linux Server Developer Installation Media',
        f'KITPro Linux Server 1.0 {status} Installation Media',
    )
    if f'iso_version="{version}"' not in text:
        raise kitpro_repo.PipelineError("qualification profile unexpectedly has release identity")
    definition.write_text(text)
    for entry in (profile / 'efiboot/loader/entries').glob('*.conf'):
        entry.write_text(entry.read_text().replace('(Development)', f'(1.0 {status})').replace(
            'Developer Shell', f'{status} Shell'))
    live = profile / 'airootfs'
    (live / 'etc/pacman.conf').write_text(production_pacman_config())
    (live / 'etc/os-release').write_text(
        f'NAME="KITPro Linux Server"\nPRETTY_NAME="KITPro Linux Server 1.0 {status}"\n'
        'ID=kitpro-linux-installer\nID_LIKE=arch\nVERSION_ID="1.0"\n'
        f'BUILD_ID="{version}"\nHOME_URL="https://kitpro.us/"\n'
    )
    (live / 'etc/motd').write_text(
        f'KITPro Linux Server 1.0 {status} installation media.\n'
        'Use kitpro-installer, kitpro-rescue, or kitpro-support-bundle.\n'
    )
    shell = live / 'root/.bash_profile'
    shell.write_text(shell.read_text().replace('KITPro Linux Server development shell',
                                             'KITPro Linux Server qualification shell'))
    project = live / 'opt/kitpro-linux'
    (project / 'tools').mkdir(parents=True)
    for name in RUNTIME_MODULES:
        shutil.copy2(source / 'tools' / name, project / 'tools' / name)
    shutil.copytree(source / 'tools/install', project / 'tools/install',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    shutil.copytree(source / 'runtime', project / 'runtime')
    shutil.copytree(source / 'schemas', project / 'schemas')
    (project / 'config/rootfs').mkdir(parents=True)
    for name in ('mkinitcpio.conf', '10-persistent.conf'):
        shutil.copy2(source / 'config/rootfs' / name, project / 'config/rootfs' / name)
    install_profile = json.loads((source / 'config/production-install-rootfs-profile.json').read_text())
    install_profile.update(
        release='1.0', generation=GENERATION,
        explicit_packages=[p['name'] for p in manifest['packages'] if p['explicit']],
        repository_url='https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/$arch',
    )
    kitpro_repo.atomic_write_json(project / 'config/install-rootfs-profile.json', install_profile)
    destination = project / 'repo/stable/1.0' / GENERATION
    shutil.copytree(generation, destination)
    phase5._stage_operator_tooling(source, live)
    installer = live / 'usr/local/bin/kitpro-installer'
    installer.write_text(installer.read_text().replace('the development shell', 'the maintenance shell'))
    validate_presentation(live, profile / 'efiboot/loader/entries')
    keyring = next(p for p in manifest['packages'] if p['name'] == 'kitpro-linux-keyring')
    if keyring['sha256'] != KEYRING_SHA256:
        raise kitpro_repo.PipelineError('production bootstrap keyring differs')
    for suffix in ('gpg', 'trusted', 'revoked'):
        name = 'kitpro-linux.' + suffix if suffix == 'gpg' else 'kitpro-linux-' + suffix
        data = kitpro_repo.run([
            'bsdtar', '-xOf', str(destination / 'core/os/x86_64' / keyring['filename']),
            'usr/share/pacman/keyrings/' + name,
        ], text=False).stdout
        target = live / 'usr/share/pacman/keyrings' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    # Build-only Arch snapshot configuration stays outside the live filesystem.
    cache = run / 'cache'
    cache.mkdir()
    kitpro_repo.render_template(profile / 'pacman.conf.in', profile / 'pacman.conf', {
        'CACHE_PATH': str(cache), 'ARCH_GPG_PATH': '/etc/pacman.d/gnupg',
        'LOG_PATH': str(run / 'archiso-pacman.log'), 'SNAPSHOT_DATE': phase4_media.SNAPSHOT_DATE,
    })
    (profile / 'pacman.conf.in').unlink()
    configuration = {
        'schema_version': 1, 'qualification_only': identity['qualification_only'], 'media_version': version,
        'iso_filename': identity['filename'], 'source_git_commit': commit,
        'source_date_epoch': manifest['source']['epoch'],
        'profile_sha256': phase4_media.tree_sha256(profile_source),
        'installation_engine_sha256': phase5._tracked_source_tree_sha256(source, 'tools/install'),
        'stable_generation': GENERATION, 'generation_manifest_sha256': PINS[GENERATION],
        'generation_artifact_set_sha256': manifest['artifact_set_sha256'],
        'worker_lock_sha256': kitpro_repo.sha256_file(source / 'ci/worker-lock.json'),
        'package_count': manifest['package_count'],
        'explicit_package_count': manifest['explicit_package_count'],
        'squashfs_processors': phase5.validate_squashfs_processor_policy(
            phase5.effective_squashfs_options(definition)),
    }
    if release_policy is not None:
        configuration['release_policy_sha256'] = kitpro_repo.sha256_file(release_policy)
    configuration['build_configuration_sha256'] = kitpro_repo.sha256_bytes(
        kitpro_repo.canonical_json_bytes(configuration))
    media = project / 'media'
    media.mkdir()
    kitpro_repo.atomic_write_json(media / 'build-configuration.json', configuration)
    metadata = {
        'kind': identity['kind'], 'media_version': version,
        'product_name': 'KITPro Linux Server', 'product_version': '1.0',
        'release_status': status, 'repository_release': '1.0',
        'repository_generation': GENERATION, 'media_build_identity': version,
        'source_git_commit': commit, 'profile_sha256': configuration['profile_sha256'],
        'build_configuration_sha256': configuration['build_configuration_sha256'],
    }
    kitpro_repo.atomic_write_json(media / 'source-metadata.json', metadata)
    load_source_metadata(media / 'source-metadata.json')
    kitpro_repo.atomic_write_json(run / 'production-input-verification.json', {
        'generation': GENERATION, 'manifest_sha256': PINS[GENERATION],
        'artifact_set_sha256': manifest['artifact_set_sha256'], 'result': 'passed',
    })
    return profile, configuration


# These upstream crypto/parser files contain public test vectors or armor
# delimiters. Never waive a match based on filename alone: require the exact
# bytes from an independently signature-verified upstream package.
UPSTREAM_LITERAL_FILES = {
    'usr/bin/gnutls-cli': 'gnutls',
    'usr/bin/ssh': 'openssh', 'usr/bin/ssh-add': 'openssh',
    'usr/bin/ssh-keygen': 'openssh', 'usr/bin/sshd': 'openssh',
    'usr/lib/ssh/ssh-keysign': 'openssh',
    'usr/lib/libgnutls.so.30.42.0': 'gnutls',
    'usr/lib/libssh2.so.1.0.1': 'libssh2',
    'usr/lib/libtss2-fapi.so.1.0.0': 'tpm2-tss',
    'usr/share/file/misc/magic.mgc': 'file',
}


def classify_upstream_literals(root: Path, cache: Path, home: Path, findings: list) -> tuple[list, list]:
    remaining, classified = [], []
    verified = {}
    for finding in findings:
        relative = finding['path']
        owner = UPSTREAM_LITERAL_FILES.get(relative)
        if finding.get('kind') != 'private-key-armor' or owner is None:
            remaining.append(finding)
            continue
        if owner not in verified:
            databases = []
            for description in (root / 'var/lib/pacman/local').glob('*/desc'):
                fields = description.read_text().split('\n\n')
                metadata = {part.splitlines()[0]: part.splitlines()[1:] for part in fields if part.strip()}
                if metadata.get('%NAME%') == [owner]:
                    databases.append(metadata)
            if len(databases) != 1:
                raise kitpro_repo.PipelineError('upstream literal package ownership is ambiguous')
            version = databases[0]['%VERSION%'][0]
            packages = list(cache.glob(f'{owner}-{version}-*.pkg.tar.zst'))
            if len(packages) != 1:
                raise kitpro_repo.PipelineError('upstream literal package bytes are unavailable')
            package = packages[0]
            signer = kitpro_repo.verify_signature(home, package.with_name(package.name + '.sig'), package)
            verified[owner] = (package, signer)
        package, signer = verified[owner]
        payload = kitpro_repo.run(['bsdtar', '-xOf', str(package), relative], text=False).stdout
        actual = (root / relative).read_bytes()
        if not payload or actual != payload:
            raise kitpro_repo.PipelineError('upstream literal file differs from signed package')
        classified.append({
            **finding, 'classification': 'unchanged upstream public fixture or parser literal',
            'package': package.name, 'package_sha256': kitpro_repo.sha256_file(package),
            'package_signer': signer, 'file_sha256': kitpro_repo.sha256_bytes(actual),
        })
    return remaining, classified


def verify_media(manifest_path: Path, output: Path, release_policy: Path | None = None) -> dict:
    from tools import production_generation
    from tools.production_packages import FINGERPRINTS
    from tools.production_repository import contamination_findings

    identity = release_identity(Path(__file__).resolve().parents[1], release_policy)
    build = kitpro_repo.load_json(manifest_path)
    phase5.validate_build_manifest(build, expected_generation=GENERATION)
    iso = Path(build['iso_path'])
    if iso.name != identity['filename'] or kitpro_repo.sha256_file(iso) != build['iso_sha256']:
        raise kitpro_repo.PipelineError('qualification ISO identity or bytes differ')
    output.mkdir(parents=True, exist_ok=False)
    extracted, root = output / 'iso', output / 'rootfs'
    boot = phase5._run_logged([
        'xorriso', '-indev', str(iso), '-report_el_torito', 'plain', '-report_system_area', 'plain'
    ], output / 'boot-metadata.txt')
    uefi, no_bios = phase5._boot_mode_checks(boot)
    if not uefi or not no_bios:
        raise kitpro_repo.PipelineError('qualification media boot layout differs')
    phase5._run_logged(['xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract', '/', str(extracted)],
                       output / 'iso-extraction.log')
    squashfs = list(extracted.glob('*/x86_64/airootfs.sfs'))
    if len(squashfs) != 1:
        raise kitpro_repo.PipelineError('expected exactly one live root filesystem')
    phase5._run_logged(['unsquashfs', '-no-progress', '-d', str(root), str(squashfs[0])],
                       output / 'unsquashfs.log')
    project = root / 'opt/kitpro-linux'
    metadata = load_source_metadata(project / 'media/source-metadata.json')
    if metadata['kind'] != identity['kind'] or metadata['release_status'] != identity['status']:
        raise kitpro_repo.PipelineError('media release status differs')
    if (metadata['product_version'] != '1.0' or metadata['repository_generation'] != GENERATION
            or metadata['media_build_identity'] != identity['version']):
        raise kitpro_repo.PipelineError('qualification installer identity differs')
    if (root / 'etc/pacman.conf').read_text() != production_pacman_config():
        raise kitpro_repo.PipelineError('live repository policy differs')
    if 'VERSION_ID="1.0"' not in (root / 'etc/os-release').read_text():
        raise kitpro_repo.PipelineError('live product version differs')
    for relative in ('usr/local/bin/kitpro-install', 'usr/local/bin/kitpro-installer',
                     'usr/local/bin/kitpro-rescue', 'usr/bin/kitpro-support-bundle',
                     'usr/bin/kitpro-health', 'usr/bin/kitpro-kernel-status'):
        path = root / relative
        if not path.is_file() or not path.stat().st_mode & 0o111:
            raise kitpro_repo.PipelineError('required live tool is missing or not executable')
    entries = extracted / 'loader/entries'
    if not entries.exists():
        candidates = list(extracted.glob('**/loader/entries'))
        if not candidates:
            raise kitpro_repo.PipelineError('boot menu entries missing')
        entries = candidates[0]
    validate_presentation(root, entries)
    menus = '\n'.join(path.read_text() for path in entries.glob('*.conf'))
    for marker in ('kitpro.mode=install', 'kitpro.mode=rescue', 'nomodeset'):
        if marker not in menus:
            raise kitpro_repo.PipelineError('required boot menu mode missing')
    raw_findings = phase5._scan_secrets(root)
    upstream_home = output / 'upstream-verification'
    rings = root / 'usr/share/pacman/keyrings'
    kitpro_repo.initialize_public_keyring(upstream_home, rings / 'archlinux.gpg',
                                         rings / 'archlinux-trusted', rings / 'archlinux-revoked')
    try:
        findings, upstream_literals = classify_upstream_literals(
            root, manifest_path.parent / 'cache', upstream_home, raw_findings)
    finally:
        kitpro_repo.run(['gpgconf', '--homedir', str(upstream_home), '--kill', 'all'])
    for surface in (root / 'etc', root / 'usr/share/pacman/keyrings',
                    root / 'usr/lib/kitpro-linux', project / 'config', project / 'media'):
        findings.extend(contamination_findings(surface))
    if (project / '.state/dev-keys').exists() or findings:
        raise kitpro_repo.PipelineError(f'qualification media contamination: {findings}')
    generation = project / 'repo/stable/1.0' / GENERATION
    manifest = validate_generation(generation, PINS[GENERATION])
    rings = root / 'usr/share/pacman/keyrings'
    trusted = output / 'trusted'
    revoked = output / 'revoked'
    trusted.write_bytes((rings / 'kitpro-linux-trusted').read_bytes() + b'\n' + (rings / 'archlinux-trusted').read_bytes())
    revoked.write_bytes((rings / 'kitpro-linux-revoked').read_bytes() + b'\n' + (rings / 'archlinux-revoked').read_bytes())
    home = output / 'public-verification'
    kitpro_repo.initialize_public_keyring(home, rings / 'kitpro-linux.gpg', trusted, revoked,
                                         additional_public_keyrings=(rings / 'archlinux.gpg',))
    fingerprints = kitpro_repo.run(['gpg', '--homedir', str(home), '--with-colons', '--show-keys',
                                   str(rings / 'kitpro-linux.gpg')]).stdout
    found = {line.split(':')[9] for line in fingerprints.splitlines() if line.startswith('fpr:')}
    if found != {FINGERPRINTS[role] for role in ('root', 'package', 'repository')}:
        raise kitpro_repo.PipelineError('production pacman trust roles differ')
    directory = generation / 'core/os/x86_64'
    production_generation.validate_inventory(manifest, directory, home, home)
    database = directory / manifest['database']['filename']
    if kitpro_repo.verify_signature(home, database.with_name(database.name + '.sig'), database) != FINGERPRINTS['repository']:
        raise kitpro_repo.PipelineError('embedded repository signature authority differs')
    from tools.release_sbom import write_media_sboms
    sbom_hashes = write_media_sboms(root, manifest_path.parent / 'cache', manifest,
                                   build['iso_sha256'], output)
    boot_images = output / 'boot-images'
    boot_images.mkdir()
    phase5._run_logged(['xorriso', '-osirrox', 'on', '-indev', str(iso), '-extract_boot_images', str(boot_images)],
                       output / 'boot-extraction.log')
    report = {
        'schema_version': 1, 'status': 'passed', 'qualification_only': identity['qualification_only'],
        'iso_sha256': build['iso_sha256'], 'squashfs_sha256': kitpro_repo.sha256_file(squashfs[0]),
        'boot_images_sha256': phase5._inventory_hash(phase5._rootfs_content_inventory(boot_images)),
        'generation': GENERATION, 'generation_manifest_sha256': PINS[GENERATION],
        'package_count': 199, 'explicit_package_count': 36, 'uefi_only': True,
        'production_trust': sorted(found), 'package_and_database_signatures': 'passed',
        'active_configuration_contamination': 'passed', 'public_secret_scan': 'passed',
        'raw_secret_scan_findings': raw_findings, 'verified_upstream_literals': upstream_literals,
        'source_metadata': metadata, 'sbom_sha256': sbom_hashes, 'sbom_schema_validation': 'pending-external-validator',
    }
    kitpro_repo.atomic_write_json(output / 'static-media-validation.json', report)
    kitpro_repo.run(['gpgconf', '--homedir', str(home), '--kill', 'all'])
    phase5._remove_readonly_extraction(root)
    phase5._remove_readonly_extraction(extracted)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--source', type=Path, required=True)
    build.add_argument('--generation', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--build-id', required=True)
    build.add_argument('--release-policy', type=Path)
    verify = commands.add_parser('verify')
    verify.add_argument('--manifest', type=Path, required=True)
    verify.add_argument('--output', type=Path, required=True)
    verify.add_argument('--release-policy', type=Path)
    compare = commands.add_parser('compare')
    compare.add_argument('--first', type=Path, required=True)
    compare.add_argument('--second', type=Path, required=True)
    compare.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'build':
        result = phase5.build(args.source, args.generation, args.output, args.build_id,
                              production_qualification=True, release_policy=args.release_policy)
    elif args.command == 'verify':
        result = verify_media(args.manifest, args.output, args.release_policy)
    else:
        result = phase5.compare_builds(args.first, args.second, args.output)
        if not result['iso_bit_for_bit_identical'] or not result['iso_sizes_identical']:
            result['status'] = 'failed'
            kitpro_repo.atomic_write_json(args.output, result)
            raise kitpro_repo.PipelineError('qualification builds are not identical')
        for path in (args.first, args.second):
            build = kitpro_repo.load_json(path)
            if kitpro_repo.sha256_file(Path(build['iso_path'])) != build['iso_sha256']:
                raise kitpro_repo.PipelineError('comparison artifact bytes changed')
    print(json.dumps(result, indent=2))
