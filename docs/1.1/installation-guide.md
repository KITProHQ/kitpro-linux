# Install KITPro Linux Server 1.1

## Before installation

1. Verify the ISO and signed checksum metadata using the
   [verification guide](verification-guide.md).
2. Back up every disk that may contain valuable data.
3. Boot in UEFI mode with Secure Boot disabled.
4. Confirm the installer's displayed model, serial or WWN, capacity, transport,
   mount state, and eligibility reason before selecting a target.

The installer keeps ineligible disks visible for diagnostics but does not allow
them to be selected. Missing, stale, ambiguous, read-only, installation-media,
and running-system identities fail closed.

Choose Quick Installation for the standard ext4 layout, or Guided Custom for
encryption, LVM, Btrfs, preservation, and EFI-reuse choices. Review the complete
plan and disk identity, then enter the explicit destructive confirmation only
for the intended target.

After installation completes, remove the installation media and boot the
installed system. Verify release identity, kernel, network, AppArmor, and
systemd health before placing the server into service.
