# KITPro Linux Server 1.1 release notes

Status: local release candidate; not published

KITPro Linux Server 1.1 introduces the final KITPro Installer 1.2.0 runtime,
release-scoped `stable/1.1` package-generation support, Linux 6.18 LTS, and
stronger installation-target identity and eligibility checks.

## Highlights

- Native Textual installer with Quick, Guided Custom, and manual GPT layouts.
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
checkpoints, and snapshot recovery. Linux 1.1 physical-hardware qualification
and offline ISO signing are not claimed until those separate gates complete.
