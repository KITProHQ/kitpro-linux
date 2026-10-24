# RC3 qualification status

Status: `QUALIFIED_1.0_RELEASE_CANDIDATE`.

KITPro Linux Server 1.0 RC3 passed the required publication-preparation
qualification:

- reproducible A/B media builds
- static media and SPDX validation
- fresh virtual installations at 2 GiB RAM under KVM and TCG
- production repository and update compatibility
- previous-kernel retention, manual fallback, and return to current
- live and offline sanitized support-bundle checks
- read-only rescue checks
- physical installation and lifecycle checks
- detached-signature verification with a public-only keyring
- 14-day physical burn-in, including three warm reboots and two clean cold cycles

The burn-in completed with every required event, healthy daily checks, and zero
defects. This summary omits raw host, storage, network, and support-bundle
evidence because those records are private qualification material.

## Frozen product relationship

- Source commit: `14e5b36cc1b02632ab729a65d206fd36accfac47`
- Source tree: `9c711fea80eb6d5def1aaae310fcb46d325c13b5`
- ISO: `kitpro-linux-server-1.0-rc3-x86_64.iso`
- ISO SHA-256: `b65845c13d8a04cea7df5cb4b346f6048cbac19bf8bb9e0cdc7d7a4162b99e6c`
- SquashFS SHA-256: `ec4412130042949c5f85f8f9cec1c52ab66b67de862e05ed519c4301f5372f94`
- Boot inventory SHA-256: `be524eaaec2b4e301fd1a0a0ca8fd7642c2790619fb67b6332f6f552a48992ba`
- ISO package SBOM SHA-256: `fd7c4ddc882c40f642031ee3f989f3325d7188bcd9ecb83dda6710cde9a2e76d`
- Production generation: `1.0-g0002`
- Package inventory: 199 total, 36 explicit
- Kernel: `6.18.55-1`

The public source mapping contains 66 frozen product inputs. Each mapped file is
byte-identical to the qualified private source. Documentation added after the
freeze does not alter those product inputs or the signed RC3 media.

No public repository, tag, release, or final 1.0 publication is claimed here.
