# KITPro Linux Server

KITPro Linux Server is an Arch Linux-derived, x86_64 server distribution with
controlled package promotion, a native Textual installer, encrypted storage,
previous-kernel fallback, offline rescue, and local sanitized support bundles.

This is the local sanitized source candidate for KITPro Linux Server 1.1. The
candidate is not published. Physical Linux 1.1 qualification, offline ISO
signature verification, repository publication, and public release remain
separate approval gates.

## Release candidate

- Version: `1.1.0`
- Generation: `1.1-g0001`
- Kernel: `linux-lts 6.18.59-1`
- Installer: `1.2.0`
- Planner: `1.8.0`
- Adapter: `0.5.0`
- KITPro Console: optional and absent from the default installation

See the [release notes](docs/1.1/release-notes.md),
[installation guide](docs/1.1/installation-guide.md),
[upgrade guide](docs/1.1/upgrade-guide.md), and
[verification guide](docs/1.1/verification-guide.md).

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
