# KITPro Linux Server

KITPro Linux Server is an Arch Linux-derived, x86_64 server distribution with
controlled package promotion, a native Textual installer, encrypted storage,
previous-kernel fallback, offline rescue, and local sanitized support bundles.

**KITPro Linux Server 1.1.0 is released and supported.** It was published on
November 1, 2026, with support through November 1, 2027. Download the ISO and
verification material from the [official 1.1.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.1.0).

The released sanitized source is commit
`6c69815ce7f62302495a7f8f76670849ff195073`. The signed release artifacts and
production generation remain unchanged by this documentation update.

## Linux 1.1 release

- Version: `1.1.0`
- Generation: `1.1-g0001`
- Kernel: `linux-lts 6.18.59-1`
- Included Installer component: `1.2.0`
- Planner: `1.8.0`
- Adapter: `0.5.1`
- KITPro Console: optional and absent from the default installation

See the [published release notes](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.1.0),
[installation guide](docs/1.1/installation-guide.md),
[upgrade guide](docs/1.1/upgrade-guide.md), and
[verification guide](docs/1.1/verification-guide.md).

Release qualification included three disposable-QEMU installation paths, a physical
Quick-ext4 installation and boot on the qualified Beelink system, a
production-signed 1.0-to-1.1 upgrade, kernel fallback, interruption recovery,
and offline ISO-metadata signing. These results apply only to the exact
artifacts listed in the release documentation.

Installer 1.2.0 is an included component, not a separate public release.
KITPro Console is in active development and has no stable Console release.
Its earlier public alphas retain the KITPro Server name. Existing
`kitpro-server` package, service, path, and API identities remain unchanged.

## Qualified scope

Secure Boot is unsupported. General dual boot, RAID, and advanced multi-disk
configurations are not qualified. Follow the version-specific installation
guide and known limitations rather than assuming that a development storage
feature is qualified for your hardware or disk layout. Back up required data
and review every target before approving disk changes.

## Linux 1.0

KITPro Linux Server 1.0 remains available from the
[official v1.0.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.0.0).
Its published source, assets, and support record remain unchanged by the 1.1
release.

## Requirements

- x86_64 processor
- UEFI firmware with Secure Boot disabled
- 2 GiB RAM minimum; 4 GiB or more recommended
- 16 GiB target disk minimum; 32 GiB or larger SSD/NVMe recommended
- 4 GiB or larger installer USB drive
- supported wired network adapter

## Build and test

The public source intentionally excludes private infrastructure, raw
qualification evidence, signing homes, internal endpoints, and credentials.
Production package generations and the Installer wheel bundle are external,
hash-pinned inputs.

Run the public test suite with:

```bash
python -m pytest -q
```

KITPro-authored source and documentation are licensed under
[Apache License 2.0](LICENSE) unless otherwise noted. Third-party materials
retain their respective licenses. KITPro is independent of Arch Linux; Arch
Linux does not sponsor, endorse, or support KITPro Linux Server.
