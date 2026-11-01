# KITPro Linux Server 1.1 release notes

Status: signed release candidate; not published

KITPro Linux Server 1.1 introduces the final KITPro Installer 1.2.0 runtime,
release-scoped `stable/1.1` package-generation support, Linux 6.18 LTS, and
stronger installation-target identity and eligibility checks.

## Highlights

- Native Textual installer with Quick and Custom workflows, including manual
  GPT layouts.
- ext4, Btrfs, native LUKS2, LVM, and LVM-on-LUKS2 support.
- Preservation-aware installation and compatible EFI System Partition reuse.
- Fresh disk-identity and eligibility validation immediately before destructive
  execution.
- Package-manager-backed transition from Linux 1.0 generation `1.0-g0002`.
- Retained previous-kernel entry for manual fallback.
- AppArmor-enabled Linux LTS kernel `6.18.59-1`.
- KITPro Console remains optional and is not installed or enabled by default.

The release candidate passed disposable QEMU installation for Quick ext4,
LVM-on-LUKS2 with encrypted swap, and preservation/EFI reuse. It also passed a
production-signed package-manager upgrade, kernel fallback, interruption
checkpoints, and snapshot recovery. Quick ext4 installation and ISO-free boot
passed on an AZW Beelink ME Pro. The exact candidate.17 checksum and release
manifests were signed offline and independently verified with a public-only
keyring.

Secure Boot, RAID, general dual boot, advanced multi-disk layouts, and universal
physical-hardware support are not claimed.
