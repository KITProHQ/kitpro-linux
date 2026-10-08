# Install KITPro Linux Server 1.0 RC2

Draft procedure. Execute only after signed RC2 media is available and verified.

1. Verify SHA256SUMS and the release manifest as described in the verification guide.
2. Write the exact verified ISO to a USB drive of at least 4 GiB. Identify the
   destination by current model, serial, and capacity. Writing the image destroys
   the USB contents; do not use a remembered device path.
3. Boot the USB in UEFI mode with Secure Boot disabled. Select the normal install
   entry. Use compatibility graphics only when the normal console is unusable.
4. Confirm that the guided installer displays KITPro Linux Server 1.0 RC2.
5. Identify the internal target disk by current model, serial, and capacity.
   Back up any required contents before proceeding. Installation replaces the
   entire selected disk with GPT, an EFI System Partition, and an ext4 root.
6. Enter the hostname, timezone, locale, network settings, administrator username,
   and local password. SSH is optional and requires a public key when enabled.
7. Review the target and settings. Enter the installer's exact ERASE confirmation
   only for the identified disk. Do not reuse an authorization from an earlier boot.
8. Follow the completion instructions, shut down, remove the USB, and boot the
   installed system. Log in locally and verify password-backed sudo.
9. Run `kitpro-health`, `kitpro-kernel-status`, and `uname -r`. The fresh RC2
   target must report production 1.0-g0002 and 6.18.55-1-lts.
10. Confirm the sole configured repository is kitpro-1.0-core at
    `https://repo.kitpro.us/kitpro-linux/stable/1.0/current/core/os/$arch`.

A fresh g0002 installation does not yet have a previous kernel. Previous-known-good
retention is established by a genuine qualified kernel update. Booting a retained
previous kernel does not downgrade the package database.
