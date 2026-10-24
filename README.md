# KITPro Linux Server

KITPro Linux Server is an Arch Linux-derived, x86_64 server distribution with
controlled package promotion, a guided whole-disk installer, manual
previous-kernel fallback, an offline rescue environment, and local sanitized
support bundles.

This repository is the unpublished source candidate for KITPro Linux Server
1.0. The RC3 product passed virtual qualification, physical lifecycle checks,
offline signature verification, and a 14-day physical burn-in with all required
boot events and no defects. It is a qualified 1.0 release candidate pending
publication authorization. It is not a released 1.0 product.

## Requirements

- x86_64 processor
- UEFI firmware with Secure Boot disabled
- 2 GiB RAM minimum, 4 GiB or more recommended
- 16 GiB target disk minimum, 32 GiB or larger SSD/NVMe recommended
- 4 GiB or larger installer USB drive
- supported network adapter, with wired Ethernet recommended

See [hardware requirements](docs/rc3/hardware-support.md) and
[known limitations](docs/rc3/known-limitations.md) before installation.

## Install and verify

- [Installation guide](docs/rc3/installation-guide.md)
- [Artifact verification](docs/rc3/verification-guide.md)
- [Release notes](docs/rc3/release-notes.md)
- [Support period](docs/rc3/support-and-eol.md)
- [Release artifact inventory](docs/rc3/artifacts.md)

## Build and test

The product source in this repository maps to frozen RC3 source commit
`14e5b36cc1b02632ab729a65d206fd36accfac47`, tree
`9c711fea80eb6d5def1aaae310fcb46d325c13b5`. Production generation artifacts
are external, public, hash-pinned build inputs.

Build the locked Arch worker locally:

```bash
docker build -f ci/arch-worker.Containerfile -t kitpro-rc-worker .
```

Run the public test and source checks:

```bash
bash ci/phase6-fast.sh
```

Build and validate non-release qualification media with the frozen generation:

```bash
python -m tools.production_media build \
  --source . \
  --generation GENERATION_DIRECTORY \
  --output OUTPUT_DIRECTORY \
  --build-id clean \
  --release-policy config/releases/1.0-rc3.json

python -m tools.production_media verify \
  --manifest BUILD_MANIFEST \
  --output VALIDATION_DIRECTORY \
  --release-policy config/releases/1.0-rc3.json
```

The locked worker and production generation are required. No private repository,
private worker registry, signing key, or private qualification record is needed.

## Licensing status

KITPro-authored source and documentation are licensed under
[Apache License 2.0](LICENSE) unless otherwise noted. Third-party and upstream
materials retain their respective licenses and notice requirements. The release
SBOMs record declared package license metadata. See [NOTICE.md](NOTICE.md).

KITPro is independent of Arch Linux. Arch Linux does not sponsor, endorse, or
support KITPro Linux Server.
