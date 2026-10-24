# Known limitations

These limits apply to the qualified KITPro Linux Server 1.0 release candidate.

- Only x86_64 UEFI systems are supported. Secure Boot and legacy BIOS are not.
- The installer replaces the selected disk. Dual boot, custom partitioning, and
  preservation of existing data on that disk are not supported.
- The installer creates an ext4 root filesystem. RAID, LVM, disk encryption,
  and ZFS installation workflows are not provided.
- Wired networking is the qualified path. DHCP and static IPv4 are supported.
  Arbitrary wireless hardware is not qualified.
- Previous-kernel selection is manual in the boot menu.
- A fresh installation has no previous kernel. Fallback becomes available after
  a genuine update retains a known-good kernel.
- SSH is optional, key-only, and denies root login.
- Offline rescue inspection mounts the root filesystem and EFI System Partition
  read-only by default. Repairs require a separate explicit action.
- Physical qualification covers one hardware class. It is not universal hardware
  certification.
- Standard support is planned for 12 months from final 1.0 publication. The
  support clock has not started.
- Final 1.0 publication, the public repository, and the `v1.0.0` tag do not yet
  exist.
