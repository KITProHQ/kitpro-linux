# KITPro Linux Server

KITPro Linux Server is an Arch-derived, x86_64 server distribution with a
curated, signed KITPro production repository. It uses UEFI, systemd-boot, and
linux-lts, with guided whole-disk installation, recovery, manually selected
previous-kernel fallback, health and support-bundle tooling, and no telemetry.
Installed systems do not use direct Arch Linux repositories.

**KITPro Linux Server 1.0 is officially released.** It was published on
October 24, 2026. Standard support runs from October 24, 2026 through
October 24, 2027. See the [official 1.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.0.0)
and the [KITPro Linux Server website](https://kitpro.us/linux-server).

The final release uses the exact ISO qualified during the RC3 cycle. Its
filename retains `rc3` because the artifact was promoted without rebuilding or
renaming it. Qualification included virtual and physical checks, offline
signature verification, and a 14-day physical burn-in with all required boot
events and zero recorded defects.

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

- [Download the official 1.0 ISO](https://github.com/KITProHQ/kitpro-linux/releases/download/v1.0.0/kitpro-linux-server-1.0-rc3-x86_64.iso)
- [Official 1.0 release](https://github.com/KITProHQ/kitpro-linux/releases/tag/v1.0.0)
- [Installation guide](docs/rc3/installation-guide.md)
- [Hardware requirements](docs/rc3/hardware-support.md)
- [Known limitations](docs/rc3/known-limitations.md)
- [Artifact verification](docs/rc3/verification-guide.md)
- [Release notes](docs/rc3/release-notes.md)
- [Support period](docs/rc3/support-and-eol.md)
- [Release artifact inventory](docs/rc3/artifacts.md)

The guided installer erases the selected target disk. Back up required data
and verify the disk before confirming installation.

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
